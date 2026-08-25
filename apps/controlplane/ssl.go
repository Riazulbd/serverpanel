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

// sslCapabilityResult mirrors packages/capabilities.sslResult — every
// ssl.* capability returns this same shape, which is what lets one
// persistence helper (persistSSLResult) back all three endpoints below.
type sslCapabilityResult struct {
	Domain    string `json:"domain"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires_at"`
	DaysLeft  int    `json:"days_left"`
	Message   string `json:"message"`
}

// persistSSLResult parses an ssl.* capability's JSON detail and, only on
// success, records it on the site row — the same "a raw task result alone
// doesn't establish a durable fact" pattern handleCreateSite/
// handleCreateBackup use.
func (a *apiServer) persistSSLResult(serverID, siteID string, detail string) (sslCapabilityResult, error) {
	var result sslCapabilityResult
	if err := json.Unmarshal([]byte(detail), &result); err != nil {
		return result, fmt.Errorf("succeeded on the agent but its result could not be parsed: %w", err)
	}
	if err := a.store.updateSiteSSL(serverID, siteID, result.Status, result.ExpiresAt); err != nil {
		return result, fmt.Errorf("succeeded on the agent but could not be recorded: %w", err)
	}
	return result, nil
}

// handleIssueSSL dispatches ssl.issue_letsencrypt for a site's own domain
// (never a caller-supplied domain — see the doc comment on handleCreateSite
// for why site-scoped endpoints read fields off the stored record instead
// of trusting the request body for anything that identifies *what* is being
// acted on).
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
		writeErr(w, http.StatusBadRequest, "email is required (Let's Encrypt expiry/urgent notices)")
		return
	}

	// Certificate issuance involves a real ACME challenge round trip over
	// the network; the default 120s dispatch timeout is tight for that.
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

	result, err := a.persistSSLResult(serverID, siteID, ev.Detail)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate issued but "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s expires_at=%s", siteID, site.Domain, result.ExpiresAt))
	writeJSON(w, http.StatusOK, result)
}

// handleCheckSSLRenewal dispatches ssl.check_renewal for a site's domain —
// a read-only status refresh, not an issuance, so it gets the normal 120s
// dispatch timeout.
func (a *apiServer) handleCheckSSLRenewal(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLCheckRenewal, map[string]any{
		"domain": site.Domain,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "ssl.check_renewal failed on the agent: "+ev.Message)
		return
	}

	result, err := a.persistSSLResult(serverID, siteID, ev.Detail)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "check_renewal ran but "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.checked", fmt.Sprintf("site_id=%s domain=%s status=%s expires_at=%s", siteID, site.Domain, result.Status, result.ExpiresAt))
	writeJSON(w, http.StatusOK, result)
}

// handleInstallCustomSSL dispatches ssl.install_custom for a site's domain
// with a caller-supplied cert/key pair. The pair is validated agent-side
// (packages/capabilities.validateCertKeyPair) before anything is written to
// disk; a mismatched pair never reaches nginx.
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

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
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

	result, err := a.persistSSLResult(serverID, siteID, ev.Detail)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "custom certificate installed but "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.custom_installed", fmt.Sprintf("site_id=%s domain=%s expires_at=%s", siteID, site.Domain, result.ExpiresAt))
	writeJSON(w, http.StatusOK, result)
}
