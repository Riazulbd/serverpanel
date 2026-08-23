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

// handleListCronJobs returns the cron jobs this control plane has on record
// for one site. It reads only from local storage (not the agent), matching
// handleListBackups/handleListSites — the dashboard should stay usable even
// while a server is briefly offline.
func (a *apiServer) handleListCronJobs(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listCronJobs(serverID, siteID))
}

// handleCreateCronJob dispatches cron.create, scoped to the site's own
// system user (never a caller-supplied one — see docs/SECURITY.md's
// per-application-user isolation guarantee), and only on success persists
// the resulting record. Same dispatch-then-persist-on-success pattern as
// handleCreateBackup.
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
		Label    string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Schedule == "" || req.Command == "" {
		writeErr(w, http.StatusBadRequest, "schedule and command are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronCreate, map[string]any{
		"system_user": site.SystemUser, "schedule": req.Schedule, "command": req.Command, "label": req.Label,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil || result.ID == "" {
		writeErr(w, http.StatusInternalServerError, "cron job created on the agent but its result could not be parsed")
		return
	}

	rec, err := a.store.createCronJob(serverID, siteID, result.ID, req.Label, req.Schedule, req.Command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q", siteID, rec.ID, req.Schedule))

	writeJSON(w, http.StatusCreated, rec)
}

// handleSetCronJobEnabled dispatches cron.set_enabled for a previously
// recorded job. The site's system_user is re-derived from the site record
// (not trusted from the request), same as handleCreateCronJob.
func (a *apiServer) handleSetCronJobEnabled(w http.ResponseWriter, r *http.Request) {
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
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronSetEnabled, map[string]any{
		"system_user": site.SystemUser, "cron_id": job.AgentID, "enabled": req.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.set_enabled failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.setCronJobEnabled(serverID, cronID, req.Enabled); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job updated on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.toggled", fmt.Sprintf("site_id=%s cron_id=%s enabled=%v", siteID, cronID, req.Enabled))

	job.Enabled = req.Enabled
	writeJSON(w, http.StatusOK, job)
}

// handleDeleteCronJob dispatches cron.delete and only removes the local
// record once the agent confirms the underlying cron.d entry is gone —
// never the other way around, which would leave a job the dashboard no
// longer shows still running on the server.
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
	job, ok := a.store.getCronJob(serverID, cronID)
	if !ok || job.SiteID != siteID {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronDelete, map[string]any{
		"system_user": site.SystemUser, "cron_id": job.AgentID,
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
		writeErr(w, http.StatusInternalServerError, "cron job deleted on the agent but could not be un-recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("site_id=%s cron_id=%s", siteID, cronID))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
