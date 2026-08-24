package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
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
		PHPVersion string `json:"php_version"`
		AppType    string `json:"app_type"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "site was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	site, err := a.store.createSite(serverID, result.Domain, result.SystemUser, result.Docroot, result.AppType, result.PHPVersion)
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

// handleCheckSiteSSL dispatches the read-only ssl.status capability for a
// site's domain and persists whatever it reports (including "none", if no
// certificate is installed) — the one place the sites table's ssl_* columns
// are ever written, mirroring how handleCreateSite is the one place a site
// row itself is written. Safe to call as often as the dashboard wants;
// unlike ssl.issue_letsencrypt/ssl.install_custom it never changes anything
// on the agent.
func (a *apiServer) handleCheckSiteSSL(w http.ResponseWriter, r *http.Request) {
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

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLStatus, map[string]any{
		"domain": site.Domain,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "ssl.status failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Status    string `json:"status"`
		Issuer    string `json:"issuer"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "ssl.status ran but its result could not be parsed: "+err.Error())
		return
	}

	if err := a.store.updateSiteSSL(serverID, siteID, result.Status, result.Issuer, result.ExpiresAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "ssl status was checked but could not be recorded: "+err.Error())
		return
	}
	updated, _ := a.store.getSite(serverID, siteID)
	writeJSON(w, http.StatusOK, updated)
}
