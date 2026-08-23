package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// Cron jobs have no control-plane-side table: the crontab installed for a
// site's system user is the single source of truth (cron.list re-reads it
// live on every call), the same way a running nginx vhost is the source of
// truth for a site's status rather than a cached "enabled" flag. This
// avoids the class of bug where the dashboard and the actual server
// disagree about what cron jobs exist. What every handler below does add
// is authorization: system_user is always taken from the site record this
// route is already scoped to (a.store.getSite(serverID, siteID)), never
// from client-supplied input, so an authenticated caller can only ever
// list/create/delete cron jobs for a site they can already see.

func (a *apiServer) handleListCrons(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapCronList, map[string]any{
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
		"system_user": site.SystemUser,
		"schedule":    req.Schedule,
		"command":     req.Command,
		"label":       req.Label,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "cron.created", "site_id="+siteID+" detail="+ev.Detail)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
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
		"system_user": site.SystemUser,
		"id":          cronID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "cron.deleted", "site_id="+siteID+" cron_id="+cronID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
