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

// sslResult mirrors packages/capabilities.sslIssueResult/sslStatusResult's
// JSON shape closely enough to decode either — only the fields this
// handler actually persists or returns.
type sslResult struct {
	Domain              string `json:"domain"`
	Managed             bool   `json:"managed"`
	NotAfter            string `json:"not_after"`
	DaysUntilExpiry     int    `json:"days_until_expiry"`
	RenewalTimerActive  bool   `json:"renewal_timer_active"`
	RenewalTimerEnabled bool   `json:"renewal_timer_enabled"`
}

// handleIssueSSL dispatches ssl.issue_letsencrypt for a site's own domain
// (never a caller-supplied one — the same dispatch-then-persist-on-success
// pattern handleCreateSite and handleCreateBackup use) and records the
// resulting certificate expiry and renewal-timer state on the site.
func (a *apiServer) handleIssueSSL(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	// Let's Encrypt is emailed about this domain's certificate (expiry
	// reminders, revocation notices); the logged-in account's own email is
	// used rather than accepting an arbitrary caller-supplied address.
	email := actor

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLIssueLE, map[string]any{
		"domain": site.Domain, "email": email,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "ssl.issue_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "ssl.issue_letsencrypt failed on the agent: "+ev.Message)
		return
	}

	var result sslResult
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued on the agent but its result could not be parsed: "+err.Error())
		return
	}
	if err := a.store.updateSiteSSL(serverID, siteID, result.NotAfter, result.RenewalTimerActive); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s expires_at=%s renewal_timer_active=%v",
		siteID, site.Domain, result.NotAfter, result.RenewalTimerActive))

	site, _ = a.store.getSite(serverID, siteID)
	writeJSON(w, http.StatusOK, map[string]any{"site": site, "ssl": result})
}

// handleGetSSLStatus dispatches ssl.status for a fresh, on-agent read of a
// site's certificate and renewal-timer state (never served from the
// control plane's own cached copy, which only reflects the last issuance),
// and refreshes the persisted copy whenever the agent is reachable.
func (a *apiServer) handleGetSSLStatus(w http.ResponseWriter, r *http.Request) {
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
		// The agent being unreachable isn't a hard failure for a read-only
		// status check — fall back to the last persisted result rather
		// than erroring the whole page out.
		writeJSON(w, http.StatusOK, map[string]any{"site": site, "live": false})
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeJSON(w, http.StatusOK, map[string]any{"site": site, "live": false, "error": ev.Message})
		return
	}

	var result sslResult
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"site": site, "live": false, "error": err.Error()})
		return
	}
	a.store.updateSiteSSL(serverID, siteID, result.NotAfter, result.RenewalTimerActive)
	site, _ = a.store.getSite(serverID, siteID)
	writeJSON(w, http.StatusOK, map[string]any{"site": site, "live": true, "ssl": result})
}
