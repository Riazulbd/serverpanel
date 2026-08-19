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

// Cron jobs have no dedicated database table on the control-plane side.
// Unlike sites/backups, the managed crontab on the agent's host *is* the
// durable record (see packages/capabilities/cron.go) — every request here
// dispatches straight to the agent and returns what it reports back, so
// there is nothing that can drift out of sync with a job edited or removed
// directly on the box.

func (a *apiServer) handleListCron(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, sessionFromContext(r.Context()).Email, capabilities.CapCronList, map[string]any{
		"system_user": site.SystemUser,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.list failed on the agent: "+ev.Message)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(ev.Detail))
}

func (a *apiServer) handleCreateCron(w http.ResponseWriter, r *http.Request) {
	a.upsertCron(w, r, randID("cron"))
}

func (a *apiServer) handleUpdateCron(w http.ResponseWriter, r *http.Request) {
	a.upsertCron(w, r, r.PathValue("cronId"))
}

func (a *apiServer) upsertCron(w http.ResponseWriter, r *http.Request, id string) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Label    string `json:"label"`
		Schedule string `json:"schedule"`
		Command  string `json:"command"`
		Enabled  *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Schedule == "" || req.Command == "" {
		writeErr(w, http.StatusBadRequest, "schedule and command are required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronSet, map[string]any{
		"system_user": site.SystemUser, "id": id, "label": req.Label,
		"schedule": req.Schedule, "command": req.Command, "enabled": enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.set failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "cron.set", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q enabled=%v", siteID, id, req.Schedule, enabled))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(ev.Detail))
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

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronDelete, map[string]any{
		"system_user": site.SystemUser, "id": cronID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("site_id=%s cron_id=%s", siteID, cronID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
