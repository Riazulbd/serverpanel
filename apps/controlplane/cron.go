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

// handleCreateCronJob dispatches cron.create for one site and, only on
// agent success, persists the resulting cron job record — the same
// dispatch-then-persist-on-success pattern handleCreateBackup uses (see
// backups.go), so a record only ever exists here if it's also live on the
// actual server's crontab.
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
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Schedule == "" || req.Command == "" {
		writeErr(w, http.StatusBadRequest, "schedule and command are required")
		return
	}

	// The control plane generates the job id up front and hands it to the
	// agent, so the crontab's marker comment and this store row always
	// share the same id — cron.delete/cron.set_enabled address the agent
	// by this same id later.
	jobID := randID("cron")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronCreate, map[string]any{
		"system_user": site.SystemUser, "schedule": req.Schedule, "command": req.Command, "id": jobID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	job, err := a.store.createCronJobWithID(jobID, serverID, siteID, req.Schedule, req.Command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s job_id=%s schedule=%q command=%q", siteID, jobID, req.Schedule, req.Command))

	writeJSON(w, http.StatusCreated, job)
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

// handleSetCronJobEnabled toggles a cron job on or off. It re-dispatches
// to the agent first and only updates the store on success, so the store
// never claims a state the actual crontab doesn't have.
func (a *apiServer) handleSetCronJobEnabled(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	jobID := r.PathValue("jobId")

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

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronSetEnabled, map[string]any{
		"system_user": site.SystemUser, "id": jobID, "enabled": req.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.set_enabled failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.setCronJobEnabled(serverID, jobID, req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job updated on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.set_enabled", fmt.Sprintf("job_id=%s enabled=%v", jobID, req.Enabled))

	job, _ = a.store.getCronJob(serverID, jobID)
	writeJSON(w, http.StatusOK, job)
}

// handleDeleteCronJob dispatches cron.delete and only removes the store
// record once the agent confirms the crontab line is gone.
func (a *apiServer) handleDeleteCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	jobID := r.PathValue("jobId")

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

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronDelete, map[string]any{
		"system_user": site.SystemUser, "id": jobID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.deleteCronJob(serverID, jobID); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job deleted on the agent but could not be un-recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("job_id=%s", jobID))

	w.WriteHeader(http.StatusNoContent)
}
