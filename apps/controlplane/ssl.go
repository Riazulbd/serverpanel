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

// sslStatusResponse mirrors packages/capabilities/ssl.go's sslStatusResult
// — the JSON shape every SSL capability returns as its task detail. It is
// re-declared here (rather than imported) because it's the control plane's
// own public API response shape, not an internal agent detail; keeping
// them as separate types means a future change to one doesn't silently
// change the other's wire format.
type sslStatusResponse struct {
	Domain        string `json:"domain"`
	Source        string `json:"source"`
	NotAfter      string `json:"not_after,omitempty"`
	DaysRemaining int    `json:"days_remaining,omitempty"`
	Issuer        string `json:"issuer,omitempty"`
}

// dispatchSSLStatus asks the agent what certificate is actually installed
// for domain right now. Every SSL write endpoint below calls this after
// its own capability succeeds, rather than trusting that capability's own
// report of what it did — the same "verify what the agent actually did"
// posture handleCreateSite/handleCreateBackup use.
func (a *apiServer) dispatchSSLStatus(ctx context.Context, serverID, actor, domain string) (sslStatusResponse, error) {
	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLStatus, map[string]any{"domain": domain})
	if err != nil {
		return sslStatusResponse{}, err
	}
	if ev.Status != proto.TaskSucceeded {
		return sslStatusResponse{}, fmt.Errorf("ssl.status failed on the agent: %s", ev.Message)
	}
	var res sslStatusResponse
	if err := json.Unmarshal([]byte(ev.Detail), &res); err != nil {
		return sslStatusResponse{}, fmt.Errorf("could not parse ssl.status result: %w", err)
	}
	return res, nil
}

func (a *apiServer) persistSSLStatus(serverID, siteID string, res sslStatusResponse) {
	status := res.Source
	if status == "none" {
		status = ""
	}
	var notAfter time.Time
	if res.NotAfter != "" {
		notAfter, _ = time.Parse(time.RFC3339, res.NotAfter)
	}
	a.store.setSiteSSL(serverID, siteID, status, notAfter)
}

// handleIssueLetsEncryptSSL dispatches ssl.issue_letsencrypt for a site's
// primary domain.
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
	json.NewDecoder(r.Body).Decode(&req)
	if req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required (Let's Encrypt expiry/urgent notices)")
		return
	}

	// certbot's own ACME round trip plus an nginx reload rarely needs more
	// than a few seconds, but a slow or rate-limited ACME endpoint gets a
	// generous budget rather than a spurious timeout.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
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

	var status sslStatusResponse
	if err := json.Unmarshal([]byte(ev.Detail), &status); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued but its status could not be parsed: "+err.Error())
		return
	}
	a.persistSSLStatus(serverID, siteID, status)
	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s source=letsencrypt not_after=%s", siteID, site.Domain, status.NotAfter))
	writeJSON(w, http.StatusOK, status)
}

// handleInstallCustomSSL dispatches ssl.install_custom. The certificate and
// private key travel only over the already-authenticated, session-cookie-
// protected browser API and the mTLS agent channel; neither is ever
// written to the audit log or any other persisted record.
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

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLInstallCustom, map[string]any{
		"domain": site.Domain, "cert_pem": req.CertPEM, "key_pem": req.KeyPEM,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "ssl.custom_install_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "ssl.install_custom failed on the agent: "+ev.Message)
		return
	}

	var status sslStatusResponse
	if err := json.Unmarshal([]byte(ev.Detail), &status); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was installed but its status could not be parsed: "+err.Error())
		return
	}
	a.persistSSLStatus(serverID, siteID, status)
	a.store.log(serverID, actor, "ssl.custom_installed", fmt.Sprintf("site_id=%s domain=%s not_after=%s", siteID, site.Domain, status.NotAfter))
	writeJSON(w, http.StatusOK, status)
}

// handleRefreshSSLStatus re-queries the agent for what certificate is
// actually installed for a site's domain, rather than serving the control
// plane's last-cached copy — used both by the dashboard's "check SSL
// status" action and to pick up a certbot renewal that happened outside
// this control plane (e.g. certbot's own renewal timer).
func (a *apiServer) handleRefreshSSLStatus(w http.ResponseWriter, r *http.Request) {
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

	status, err := a.dispatchSSLStatus(ctx, serverID, actor, site.Domain)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	a.persistSSLStatus(serverID, siteID, status)
	writeJSON(w, http.StatusOK, status)
}
