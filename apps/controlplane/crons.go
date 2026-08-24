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

// handleCreateCron dispatches cron.create for one site's system user and,
// only on success, persists the resulting cron record — the same
// dispatch-then-persist-on-success pattern handleCreateSite/
// handleCreateBackup use, for the same reason: a raw task result alone
// doesn't establish that a durable cron entry now exists.
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

	id := randID("cron")

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronCreate, map[string]any{
		"system_user": site.SystemUser, "id": id, "schedule": req.Schedule, "command": req.Command,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	cron, err := a.store.createCron(id, serverID, siteID, req.Schedule, req.Command)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "cron was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s cron_id=%s schedule=%q command=%q", siteID, id, req.Schedule, req.Command))

	writeJSON(w, http.StatusCreated, cron)
}

func (a *apiServer) handleListCrons(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listCrons(serverID, siteID))
}

// handleToggleCron dispatches cron.set_enabled for one previously created
// cron entry, then updates the persisted record to match.
func (a *apiServer) handleToggleCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	cronID := r.PathValue("cronId")

	cron, ok := a.store.getCron(serverID, cronID)
	if !ok {
		writeErr(w, http.StatusNotFound, "cron not found")
		return
	}
	site, ok := a.store.getSite(serverID, cron.SiteID)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "the site this cron belongs to no longer exists on this server")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "enabled is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronSetEnabled, map[string]any{
		"system_user": site.SystemUser, "id": cron.ID, "enabled": req.Enabled,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.set_enabled failed on the agent: "+ev.Message)
		return
	}

	a.store.setCronEnabled(serverID, cronID, req.Enabled)
	a.store.log(serverID, actor, "cron.toggled", fmt.Sprintf("cron_id=%s enabled=%v", cronID, req.Enabled))
	writeJSON(w, http.StatusOK, map[string]any{"id": cronID, "enabled": req.Enabled})
}

// handleDeleteCron dispatches cron.delete for one previously created cron
// entry, then removes the persisted record only on agent-side success —
// never the other way around, so the store never claims a cron is gone
// while it's still live on the server.
func (a *apiServer) handleDeleteCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	cronID := r.PathValue("cronId")

	cron, ok := a.store.getCron(serverID, cronID)
	if !ok {
		writeErr(w, http.StatusNotFound, "cron not found")
		return
	}
	site, ok := a.store.getSite(serverID, cron.SiteID)
	if !ok {
		writeErr(w, http.StatusUnprocessableEntity, "the site this cron belongs to no longer exists on this server")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronDelete, map[string]any{
		"system_user": site.SystemUser, "id": cron.ID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	a.store.deleteCron(serverID, cronID)
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("cron_id=%s", cronID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
