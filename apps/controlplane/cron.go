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

// Cron jobs are not persisted in the control plane's own database — the
// crontab on the server is the source of truth (the same live-query
// pattern db.list uses for databases), and every handler here resolves
// the target site's system_user from the store rather than trusting a
// client-supplied username, so an authenticated caller can never point a
// cron operation at another site's system user by tampering with a
// request parameter.

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
		"user": site.SystemUser,
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

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronCreate, map[string]any{
		"user": site.SystemUser, "schedule": req.Schedule, "command": req.Command, "label": req.Label,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s schedule=%q", siteID, req.Schedule))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(ev.Detail))
}

func (a *apiServer) handleSetCronEnabled(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	cronID := r.PathValue("cronId")
	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "enabled (bool) is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronSetEnabled, map[string]any{
		"user": site.SystemUser, "id": cronID, "enabled": req.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.set_enabled failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "cron.updated", fmt.Sprintf("site_id=%s cron_id=%s enabled=%t", siteID, cronID, req.Enabled))
	w.Header().Set("Content-Type", "application/json")
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
		"user": site.SystemUser, "id": cronID,
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
