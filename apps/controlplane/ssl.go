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

// sslDispatchResult is the shape every ssl.* capability returns as its
// TaskEvent detail (packages/capabilities/ssl.go sslResult) — parsed here
// so the control plane can persist what the agent actually confirmed,
// following the same dispatch-then-persist-on-success pattern as
// handleCreateSite/handleCreateBackup.
type sslDispatchResult struct {
	Domain    string `json:"domain"`
	Type      string `json:"type"`
	Issuer    string `json:"issuer"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
}

// handleIssueLetsEncryptSSL dispatches ssl.issue_letsencrypt for a site's
// domain and, only on success, records the resulting certificate type and
// expiry against the site.
func (a *apiServer) handleIssueLetsEncryptSSL(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}

	// Certificate issuance involves a real network round-trip to Let's
	// Encrypt plus DNS-01/HTTP-01 challenge validation; give it more room
	// than the 120s default dispatch timeout other quick capabilities use.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLIssueLE, map[string]any{
		"domain": site.Domain, "email": req.Email,
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

	a.persistSSLResult(w, serverID, siteID, actor, ev.Detail)
}

// handleInstallCustomSSL dispatches ssl.install_custom, filling in the
// site's system_user/docroot/app_type/php_version from the control plane's
// own record rather than trusting the browser to supply them — the same
// reason handleCreateBackup passes site.Docroot instead of taking a
// site_root field from the request body.
func (a *apiServer) handleInstallCustomSSL(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		CertPEM string `json:"cert_pem"`
		KeyPEM  string `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.CertPEM == "" || req.KeyPEM == "" {
		writeErr(w, http.StatusBadRequest, "cert_pem and key_pem are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLInstallCustom, map[string]any{
		"domain": site.Domain, "system_user": site.SystemUser, "docroot": site.Docroot,
		"app_type": site.AppType, "php_version": site.PHPVersion, "cert_pem": req.CertPEM, "key_pem": req.KeyPEM,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "ssl.install_custom_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "ssl.install_custom failed on the agent: "+ev.Message)
		return
	}

	a.persistSSLResult(w, serverID, siteID, actor, ev.Detail)
}

// handleGetSSLStatus re-reads the certificate straight off the agent
// (rather than only returning whatever this control plane last recorded)
// and refreshes the stored ssl_type/ssl_expires_at to match, so a
// certificate renewed or replaced outside the dashboard (e.g. certbot's
// own renewal timer, see stack.go) is reflected the next time the site's
// SSL panel loads.
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

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLStatus, map[string]any{"domain": site.Domain})
	if err != nil {
		// The server may simply be offline; fall back to the last known
		// value rather than failing the whole page.
		writeJSON(w, http.StatusOK, site)
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeJSON(w, http.StatusOK, site)
		return
	}

	a.persistSSLResult(w, serverID, siteID, actor, ev.Detail)
}

func (a *apiServer) persistSSLResult(w http.ResponseWriter, serverID, siteID, actor, detailJSON string) {
	var result sslDispatchResult
	if err := json.Unmarshal([]byte(detailJSON), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "ssl operation completed on the agent but its result could not be parsed: "+err.Error())
		return
	}
	if err := a.store.updateSiteSSL(serverID, siteID, result.Type, result.ExpiresAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "ssl operation completed on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.updated", fmt.Sprintf("site_id=%s domain=%s type=%s expires_at=%s", siteID, result.Domain, result.Type, result.ExpiresAt))

	site, _ := a.store.getSite(serverID, siteID)
	writeJSON(w, http.StatusOK, site)
}
