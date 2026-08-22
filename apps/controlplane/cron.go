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

// handleCreateCronJob dispatches cron.create — always for the target
// site's own system user, never a caller-supplied one, which is what
// keeps a cron job scoped to the same isolation boundary as the site
// itself — and, only on success, persists the resulting record. The
// dispatch-then-persist-on-success pattern mirrors handleCreateSite and
// handleCreateBackup for the same reason: a raw task result alone doesn't
// establish that a durable, listable cron job now exists.
//
// The job's id is generated here (not by the agent) and passed down as a
// parameter, so a retried request after a network blip lands on
// cron.create's idempotent id-already-present path on the agent instead
// of creating a duplicate schedule.
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

	id := randID("cron")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronCreate, map[string]any{
		"id": id, "user": site.SystemUser, "schedule": req.Schedule, "command": req.Command,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	job, err := a.store.createCronJob(serverID, siteID, id, req.Schedule, req.Command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron job was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q", siteID, id, req.Schedule))

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

// handleSetCronJobEnabled dispatches cron.set_enabled for one previously
// created job, scoped by serverID exactly like handleRestoreBackup scopes
// backups — a job id alone is never enough to act on it.
func (a *apiServer) handleSetCronJobEnabled(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	cronID := r.PathValue("cronId")

	job, ok := a.store.getCronJob(serverID, cronID)
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
		"id": cronID, "user": site.SystemUser, "enabled": req.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.set_enabled failed on the agent: "+ev.Message)
		return
	}

	a.store.setCronJobEnabled(cronID, req.Enabled)
	a.store.log(serverID, actor, "cron.set_enabled", fmt.Sprintf("cron_id=%s enabled=%t", cronID, req.Enabled))

	job.Enabled = req.Enabled
	writeJSON(w, http.StatusOK, job)
}

// handleDeleteCronJob dispatches cron.delete and, only on success, removes
// the control-plane record — never the reverse, so a failed agent-side
// delete never leaves the dashboard silently out of sync with what is
// still actually scheduled on the server.
func (a *apiServer) handleDeleteCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	cronID := r.PathValue("cronId")

	job, ok := a.store.getCronJob(serverID, cronID)
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
		"id": cronID, "user": site.SystemUser,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	a.store.deleteCronJob(cronID)
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("cron_id=%s site_id=%s", cronID, job.SiteID))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
