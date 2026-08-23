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

// handleCreateCron dispatches cron.upsert for a new job and, only on
// success, persists the resulting cron_jobs record — the same
// dispatch-then-persist-on-success pattern handleCreateBackup uses.
func (a *apiServer) handleCreateCron(w http.ResponseWriter, r *http.Request) {
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Schedule == "" || req.Command == "" {
		writeErr(w, http.StatusBadRequest, "schedule and command are required")
		return
	}

	// The job's id is generated here, before dispatch, so it can be embedded
	// in the crontab marker the agent writes — the control plane never lets
	// the agent (or a caller) invent the id a record is later addressed by.
	jobID := randID("cron")

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronUpsert, map[string]any{
		"system_user": site.SystemUser, "job_id": jobID, "schedule": req.Schedule, "command": req.Command, "enabled": true,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.upsert failed on the agent: "+ev.Message)
		return
	}

	job, err := a.store.createCronJobWithID(jobID, serverID, siteID, req.Schedule, req.Command, true)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q", siteID, jobID, req.Schedule))

	writeJSON(w, http.StatusCreated, job)
}

func (a *apiServer) handleListCron(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listCronJobs(serverID, siteID))
}

// handleUpdateCron re-dispatches cron.upsert with the same job_id so an
// edit (schedule/command) or an enable/disable toggle replaces the
// existing crontab entry in place rather than creating a duplicate.
func (a *apiServer) handleUpdateCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	cronID := r.PathValue("cronId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	job, ok := a.store.getCronJob(serverID, cronID)
	if !ok || job.SiteID != siteID {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}

	var req struct {
		Schedule *string `json:"schedule"`
		Command  *string `json:"command"`
		Enabled  *bool   `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	schedule, command, enabled := job.Schedule, job.Command, job.Enabled
	if req.Schedule != nil {
		schedule = *req.Schedule
	}
	if req.Command != nil {
		command = *req.Command
	}
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronUpsert, map[string]any{
		"system_user": site.SystemUser, "job_id": cronID, "schedule": schedule, "command": command, "enabled": enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.upsert failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.updateCronJob(serverID, cronID, schedule, command, enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job was updated on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.updated", fmt.Sprintf("cron_id=%s schedule=%q enabled=%v", cronID, schedule, enabled))

	updated, _ := a.store.getCronJob(serverID, cronID)
	writeJSON(w, http.StatusOK, updated)
}

func (a *apiServer) handleDeleteCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	cronID := r.PathValue("cronId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	job, ok := a.store.getCronJob(serverID, cronID)
	if !ok || job.SiteID != siteID {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronDelete, map[string]any{
		"system_user": site.SystemUser, "job_id": cronID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.deleteCronJob(serverID, cronID); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job was deleted on the agent but could not be un-recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("cron_id=%s site_id=%s", cronID, siteID))

	w.WriteHeader(http.StatusNoContent)
}
