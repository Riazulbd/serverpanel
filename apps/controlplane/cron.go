package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// cronApplyParams converts a site's cron job records into cron.apply's
// params.jobs shape. The agent never learns a job's control-plane ID — it
// only ever receives a full, ordered list of {schedule, command, comment,
// enabled} to render, and rewrites the target user's entire crontab from
// it; the control plane's cron_jobs table stays the sole record of which
// row is which.
func cronApplyParams(jobs []*cronJobRecord) []map[string]any {
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, map[string]any{
			"schedule": j.Schedule, "command": j.Command, "comment": j.Comment, "enabled": j.Enabled,
		})
	}
	return out
}

// applyCronJobs dispatches cron.apply for siteSysUser with the given job
// list and returns an error if the agent rejects or fails it. Called with a
// proposed job list built in-memory before any database write, so a bad
// schedule/command or an unreachable agent never leaves a persisted cron
// job the live crontab doesn't actually contain.
func (a *apiServer) applyCronJobs(ctx context.Context, serverID, actor, sysUser string, jobs []map[string]any) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronApply, map[string]any{
		"system_user": sysUser, "jobs": jobs,
	})
	if err != nil {
		return fmt.Errorf("dispatch: %w", err)
	}
	if ev.Status != proto.TaskSucceeded {
		return fmt.Errorf("agent: %s", ev.Message)
	}
	return nil
}

func (a *apiServer) handleListCronJobs(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listCronJobs(serverID, siteID))
}

// maxCronJobsPerSite bounds how many jobs one site can accumulate — cron.go
// (capabilities) has no per-job limit of its own since it just renders
// whatever list it's given, so the limit belongs here, at the point new
// jobs are actually admitted.
const maxCronJobsPerSite = 100

func (a *apiServer) handleCreateCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Schedule string `json:"schedule"`
		Command  string `json:"command"`
		Comment  string `json:"comment"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := capabilities.ValidateCronSchedule(req.Schedule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := capabilities.ValidateCronCommand(req.Command); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	existing := a.store.listCronJobs(serverID, siteID)
	if len(existing) >= maxCronJobsPerSite {
		writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("this site already has the maximum of %d cron jobs", maxCronJobsPerSite))
		return
	}

	proposed := cronApplyParams(existing)
	proposed = append(proposed, map[string]any{
		"schedule": req.Schedule, "command": req.Command, "comment": req.Comment, "enabled": enabled,
	})

	if err := a.applyCronJobs(r.Context(), serverID, actor, site.SystemUser, proposed); err != nil {
		writeErr(w, http.StatusBadGateway, "cron.apply failed: "+err.Error())
		return
	}

	job, err := a.store.createCronJob(serverID, siteID, req.Schedule, req.Command, req.Comment, enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job applied on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q command=%q", siteID, job.ID, job.Schedule, job.Command))
	writeJSON(w, http.StatusCreated, job)
}

func (a *apiServer) handleUpdateCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	cronID := r.PathValue("cronId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	job, ok := a.store.getCronJob(serverID, siteID, cronID)
	if !ok {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}

	var req struct {
		Schedule *string `json:"schedule"`
		Command  *string `json:"command"`
		Comment  *string `json:"comment"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	schedule, command, comment, enabled := job.Schedule, job.Command, job.Comment, job.Enabled
	if req.Schedule != nil {
		schedule = *req.Schedule
	}
	if req.Command != nil {
		command = *req.Command
	}
	if req.Comment != nil {
		comment = *req.Comment
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	if err := capabilities.ValidateCronSchedule(schedule); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := capabilities.ValidateCronCommand(command); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	all := a.store.listCronJobs(serverID, siteID)
	proposed := make([]map[string]any, 0, len(all))
	for _, j := range all {
		if j.ID == cronID {
			proposed = append(proposed, map[string]any{
				"schedule": schedule, "command": command, "comment": comment, "enabled": enabled,
			})
		} else {
			proposed = append(proposed, map[string]any{
				"schedule": j.Schedule, "command": j.Command, "comment": j.Comment, "enabled": j.Enabled,
			})
		}
	}

	if err := a.applyCronJobs(r.Context(), serverID, actor, site.SystemUser, proposed); err != nil {
		writeErr(w, http.StatusBadGateway, "cron.apply failed: "+err.Error())
		return
	}

	updated, err := a.store.updateCronJob(serverID, siteID, cronID, schedule, command, comment, enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job applied on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.updated", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q command=%q enabled=%t", siteID, cronID, schedule, command, enabled))
	writeJSON(w, http.StatusOK, updated)
}

func (a *apiServer) handleDeleteCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	cronID := r.PathValue("cronId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if _, ok := a.store.getCronJob(serverID, siteID, cronID); !ok {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}

	all := a.store.listCronJobs(serverID, siteID)
	proposed := make([]map[string]any, 0, len(all))
	for _, j := range all {
		if j.ID == cronID {
			continue
		}
		proposed = append(proposed, map[string]any{
			"schedule": j.Schedule, "command": j.Command, "comment": j.Comment, "enabled": j.Enabled,
		})
	}

	if err := a.applyCronJobs(r.Context(), serverID, actor, site.SystemUser, proposed); err != nil {
		writeErr(w, http.StatusBadGateway, "cron.apply failed: "+err.Error())
		return
	}

	if err := a.store.deleteCronJob(serverID, siteID, cronID); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job removed from the agent but could not be deleted from records: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("site_id=%s cron_id=%s", siteID, cronID))
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
