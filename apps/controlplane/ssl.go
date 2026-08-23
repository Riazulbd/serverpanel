package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleListCertificates lists certificates recorded for one site.
func (a *apiServer) handleListCertificates(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listCertificates(serverID, siteID))
}

// handleIssueLetsEncrypt dispatches ssl.issue_letsencrypt for a site and,
// only on success, persists a certificate record. The domain is always the
// site's own recorded Domain — never caller-supplied — for the same reason
// handleCreateBackup takes site_root from the site record rather than the
// request body: it keeps a caller from pointing certbot at a domain this
// server doesn't actually have a vhost for.
func (a *apiServer) handleIssueLetsEncrypt(w http.ResponseWriter, r *http.Request) {
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
	email := req.Email
	if email == "" {
		// Defaults to the requesting account's own email — Let's Encrypt
		// requires a contact address for expiry/urgent notices, and the
		// logged-in operator is the sensible default recipient absent an
		// explicit override.
		email = actor
	}

	// certbot's ACME handshake (DNS/HTTP-01 challenge + CA round trip) can
	// take a while under a slow or rate-limited CA; backup.run's dispatch
	// timeout is the closest existing precedent for a long agent operation.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLIssueLE, map[string]any{
		"domain": site.Domain, "email": email,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "ssl.issue_letsencrypt failed on the agent: "+ev.Message)
		return
	}

	cert, err := a.store.createCertificate(serverID, siteID, site.Domain, "letsencrypt")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.issued", "site_id="+siteID+" domain="+site.Domain+" issuer=letsencrypt")

	writeJSON(w, http.StatusCreated, cert)
}

// handleInstallCustomSSL dispatches ssl.install_custom for a site and, only
// on success, persists a certificate record. Certificate/key material
// passes straight through to the agent in the request body — the control
// plane never parses, logs, or stores it itself, only the resulting
// domain/issuer metadata.
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
		writeErr(w, http.StatusUnprocessableEntity, "ssl.install_custom failed on the agent: "+ev.Message)
		return
	}

	cert, err := a.store.createCertificate(serverID, siteID, site.Domain, "custom")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was installed on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.installed", "site_id="+siteID+" domain="+site.Domain+" issuer=custom")

	writeJSON(w, http.StatusCreated, cert)
}
