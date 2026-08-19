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

// handleInstallSiteSSL installs a customer-supplied certificate for one
// site. It exists as its own endpoint rather than going through generic
// task dispatch because the agent needs the site's system user, docroot,
// app type, and PHP version to generate a working TLS server block — and
// those must come from the stored site record, not from the request body.
// A caller supplying its own system_user would be choosing which site's
// nginx config gets rewritten, which is not theirs to choose.
//
// The certificate and key are passed through to the agent and are never
// persisted by the control plane: the agent writes them to the server that
// will actually serve them, and the private key exists nowhere else.
func (a *apiServer) handleInstallSiteSSL(w http.ResponseWriter, r *http.Request) {
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		writeErr(w, http.StatusBadRequest, "cert_pem and key_pem are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLInstallCustom, map[string]any{
		"domain":      site.Domain,
		"system_user": site.SystemUser,
		"docroot":     site.Docroot,
		"app_type":    site.AppType,
		"php_version": site.PHPVersion,
		"cert_pem":    req.CertPEM,
		"key_pem":     req.KeyPEM,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		// ev.Message is the agent's validation error (mismatched key, wrong
		// domain, expired certificate, nginx rejection). It is written by
		// validateCertificateMaterial specifically never to echo the
		// submitted PEM, so surfacing it here cannot leak key material.
		a.store.log(serverID, actor, "ssl.install_custom_failed", fmt.Sprintf("site_id=%s: %s", siteID, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "certificate was not installed: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "ssl.install_custom", fmt.Sprintf("site_id=%s domain=%s", siteID, site.Domain))
	writeJSON(w, http.StatusOK, map[string]string{"status": "installed", "detail": ev.Detail})
}

// handleIssueSiteSSL issues a Let's Encrypt certificate for one site. The
// domain comes from the stored site record rather than the request, so a
// caller can only ever request a certificate for a domain this control
// plane already configured a vhost for — ACME validation would fail
// otherwise anyway, but failing before burning a rate-limited request
// against Let's Encrypt is better than failing after.
func (a *apiServer) handleIssueSiteSSL(w http.ResponseWriter, r *http.Request) {
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
		writeErr(w, http.StatusBadRequest, "email is required (Let's Encrypt sends expiry and urgent notices to it)")
		return
	}

	// ACME issuance involves DNS validation and a round trip to Let's
	// Encrypt; the default 120s dispatch budget is tight for a first issue.
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLIssueLE, map[string]any{
		"domain": site.Domain, "email": req.Email,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "ssl.issue_failed", fmt.Sprintf("site_id=%s: %s", siteID, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "certificate was not issued: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s detail=%s", siteID, site.Domain, ev.Detail))
	writeJSON(w, http.StatusOK, map[string]string{"status": "issued", "detail": ev.Detail})
}
