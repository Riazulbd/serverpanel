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
// TaskEvent detail (packages/capabilities/ssl.go sslResult) — decoded here
// so the control plane can persist expiry rather than just forward the raw
// string to the browser.
type sslDispatchResult struct {
	Domain        string `json:"domain"`
	Status        string `json:"status"`
	Issuer        string `json:"issuer"`
	ExpiresAt     string `json:"expires_at"`
	DaysRemaining int    `json:"days_remaining"`
}

// recordSSLResult persists a successful ssl.* dispatch's reported status
// against the site it belongs to. A "none" status (nothing found on disk)
// is recorded as empty issuer/expiry, same as a site that has never had a
// certificate — the dashboard treats both identically.
func (a *apiServer) recordSSLResult(serverID, siteID string, ev proto.TaskEvent) (sslDispatchResult, error) {
	var res sslDispatchResult
	if err := json.Unmarshal([]byte(ev.Detail), &res); err != nil {
		return res, fmt.Errorf("agent result could not be parsed: %w", err)
	}
	issuer, expiresAt := res.Issuer, res.ExpiresAt
	if res.Status != "active" {
		issuer, expiresAt = "", ""
	}
	if err := a.store.updateSiteSSL(serverID, siteID, issuer, expiresAt); err != nil {
		return res, fmt.Errorf("SSL status was retrieved but could not be recorded: %w", err)
	}
	return res, nil
}

// handleIssueSSL dispatches ssl.issue_letsencrypt for a site's primary
// domain and records the resulting expiry on success.
func (a *apiServer) handleIssueSSL(w http.ResponseWriter, r *http.Request) {
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

	// Let's Encrypt's ACME HTTP challenge and certbot's own network calls
	// can take longer than the default dispatch budget.
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

	res, err := a.recordSSLResult(serverID, siteID, ev)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s expires_at=%s", siteID, site.Domain, res.ExpiresAt))
	writeJSON(w, http.StatusOK, res)
}

// handleInstallCustomSSL dispatches ssl.install_custom with a
// caller-supplied certificate/key pair.
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

	res, err := a.recordSSLResult(serverID, siteID, ev)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.custom_installed", fmt.Sprintf("site_id=%s domain=%s expires_at=%s", siteID, site.Domain, res.ExpiresAt))
	writeJSON(w, http.StatusOK, res)
}

// handleRefreshSSL dispatches ssl.status, a read-only check, and syncs the
// stored expiry to whatever the agent actually finds on disk — useful
// after a certificate was replaced outside our own flow, or just to
// confirm renewal happened.
func (a *apiServer) handleRefreshSSL(w http.ResponseWriter, r *http.Request) {
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
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "ssl.status failed on the agent: "+ev.Message)
		return
	}

	res, err := a.recordSSLResult(serverID, siteID, ev)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}
