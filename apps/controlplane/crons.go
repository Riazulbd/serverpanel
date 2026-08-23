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

// maxCronsPerSite bounds how many jobs a single site can accumulate. There
// is no technical crontab limit worth respecting here, but an unbounded
// count would turn every future create/delete into an ever-larger
// cron.sync payload and (more importantly) is very likely a mistake by
// whoever's driving the dashboard/API rather than a real need.
const maxCronsPerSite = 100

// cronJobSpecsFor converts a site's persisted, enabled cron jobs into the
// wire format cron.sync expects.
func cronJobSpecsFor(jobs []*cronJobRecord) []map[string]any {
	out := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		out = append(out, map[string]any{"id": j.ID, "schedule": j.Schedule, "command": j.Command})
	}
	return out
}

// syncCronsToAgent dispatches cron.sync with the current full set of
// enabled jobs for one site, so the agent's action is always "make the
// live crontab match this exact list" rather than an incremental
// add/remove the control plane and the agent could drift out of sync on.
func (a *apiServer) syncCronsToAgent(ctx context.Context, serverID, actor, systemUser string, jobs []*cronJobRecord) error {
	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(dctx, serverID, actor, capabilities.CapCronSync, map[string]any{
		"system_user": systemUser,
		"jobs":        cronJobSpecsFor(jobs),
	})
	if err != nil {
		return err
	}
	if ev.Status != proto.TaskSucceeded {
		return fmt.Errorf("cron.sync failed on the agent: %s", ev.Message)
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

// handleCreateCronJob persists the new job first (so it participates in
// the cron.sync payload below), then syncs; if the agent rejects it (bad
// schedule/command, agent unreachable), the just-created row is deleted
// again so the control plane's database never records a job that isn't
// actually live on the server — the same "don't record what didn't really
// happen" discipline handleCreateBackup applies to backups.
func (a *apiServer) handleCreateCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	if len(a.store.listCronJobs(serverID, siteID)) >= maxCronsPerSite {
		writeErr(w, http.StatusUnprocessableEntity, fmt.Sprintf("this site already has the maximum of %d cron jobs", maxCronsPerSite))
		return
	}

	var req struct {
		Schedule string `json:"schedule"`
		Command  string `json:"command"`
		Comment  string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Schedule == "" || req.Command == "" {
		writeErr(w, http.StatusBadRequest, "schedule and command are required")
		return
	}

	job, err := a.store.createCronJob(serverID, siteID, req.Schedule, req.Command, req.Comment)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := a.syncCronsToAgent(r.Context(), serverID, actor, site.SystemUser, a.store.enabledCronJobs(serverID, siteID)); err != nil {
		a.store.deleteCronJob(serverID, job.ID)
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q", siteID, job.ID, job.Schedule))
	writeJSON(w, http.StatusCreated, job)
}

// handleDeleteCronJob mirrors handleCreateCronJob's ordering in reverse:
// the row is only removed from the database after the agent confirms the
// live crontab no longer has it, so a failed sync leaves both sides
// consistent (job still present, still tracked) rather than the dashboard
// showing a job that's already gone from the actual server.
func (a *apiServer) handleDeleteCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	jobID := r.PathValue("cronId")

	job, ok := a.store.getCronJob(serverID, jobID)
	if !ok {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}
	site, ok := a.store.getSite(serverID, job.SiteID)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "the site this cron job belongs to no longer exists on this server")
		return
	}

	remaining := a.store.enabledCronJobs(serverID, job.SiteID)
	filtered := remaining[:0]
	for _, j := range remaining {
		if j.ID != jobID {
			filtered = append(filtered, j)
		}
	}

	if err := a.syncCronsToAgent(r.Context(), serverID, actor, site.SystemUser, filtered); err != nil {
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	if err := a.store.deleteCronJob(serverID, jobID); err != nil {
		writeErr(w, http.StatusInternalServerError, "removed from the live crontab but could not remove the database record: "+err.Error())
		return
	}

	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("site_id=%s cron_id=%s", job.SiteID, jobID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleToggleCronJob flips a job's enabled state and re-syncs — a
// disabled job stays a fully-defined database row (so re-enabling doesn't
// require re-entering it) but is simply excluded from the set cron.sync is
// told to write, which is what actually stops it from running.
func (a *apiServer) handleToggleCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	jobID := r.PathValue("cronId")

	job, ok := a.store.getCronJob(serverID, jobID)
	if !ok {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}
	site, ok := a.store.getSite(serverID, job.SiteID)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "the site this cron job belongs to no longer exists on this server")
		return
	}

	newEnabled := !job.Enabled
	if err := a.store.setCronJobEnabled(serverID, jobID, newEnabled); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := a.syncCronsToAgent(r.Context(), serverID, actor, site.SystemUser, a.store.enabledCronJobs(serverID, job.SiteID)); err != nil {
		a.store.setCronJobEnabled(serverID, jobID, job.Enabled) // roll back
		writeErr(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	action := "cron.disabled"
	if newEnabled {
		action = "cron.enabled"
	}
	a.store.log(serverID, actor, action, fmt.Sprintf("site_id=%s cron_id=%s", job.SiteID, jobID))
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": newEnabled})
}
