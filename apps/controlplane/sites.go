package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateSite dispatches site.create to the agent and, only on
// success, persists a site record — this is the one place the control
// plane's sites table is ever written, which is why generic capability
// dispatch (handleDispatchTask) and site creation are separate endpoints
// even though both ultimately call gateway.dispatch: a raw task result
// alone isn't enough to know a site now exists, and the JSON detail
// site.create returns (packages/capabilities/site.go siteResult) is the
// one place that fact is expressed.
func (a *apiServer) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Domain     string `json:"domain"`
		AppType    string `json:"app_type"`
		PHPVersion string `json:"php_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" || req.AppType == "" {
		writeErr(w, http.StatusBadRequest, "domain and app_type are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "site.create", map[string]any{
		"domain": req.Domain, "app_type": req.AppType, "php_version": req.PHPVersion,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "site.create failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Domain     string `json:"domain"`
		TempDomain string `json:"temp_domain"`
		SystemUser string `json:"system_user"`
		Docroot    string `json:"docroot"`
		HomeDir    string `json:"home_dir"`
		PHPVersion string `json:"php_version"`
		AppType    string `json:"app_type"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "site was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	site, err := a.store.createSite(serverID, result.Domain, result.SystemUser, result.Docroot, result.HomeDir, result.AppType, result.PHPVersion)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "site was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "site.created", "domain="+result.Domain+" temp_domain="+result.TempDomain)

	writeJSON(w, http.StatusCreated, map[string]any{
		"site":        site,
		"temp_domain": result.TempDomain,
	})
}
