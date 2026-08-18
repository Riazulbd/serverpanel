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

// sslStatusDetail mirrors packages/capabilities/ssl.go's sslStatusResult —
// the control plane never re-derives certificate state itself, only
// persists what the agent reports after reading the certificate off disk.
type sslStatusDetail struct {
	Domain          string `json:"domain"`
	Installed       bool   `json:"installed"`
	Source          string `json:"source"`
	Issuer          string `json:"issuer"`
	NotAfter        string `json:"not_after"`
	DaysRemaining   int    `json:"days_remaining"`
	AutoRenewActive bool   `json:"auto_renew_active"`
}

// persistSSLStatus dispatches ssl.status for a site and writes the result
// into the sites table, so the dashboard's site list/detail views don't
// need to round-trip to the agent just to show expiry. Used after every
// SSL-mutating operation (issue/renew/uninstall) as well as by the
// dedicated GET endpoint.
func (a *apiServer) persistSSLStatus(ctx context.Context, serverID, actor string, site *siteRecord) (*sslStatusDetail, error) {
	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLStatus, map[string]any{"domain": site.Domain})
	if err != nil {
		return nil, err
	}
	if ev.Status != proto.TaskSucceeded {
		return nil, fmt.Errorf("ssl.status failed on the agent: %s", ev.Message)
	}
	var detail sslStatusDetail
	if err := json.Unmarshal([]byte(ev.Detail), &detail); err != nil {
		return nil, fmt.Errorf("ssl.status result could not be parsed: %w", err)
	}

	var expiresAt *time.Time
	if detail.Installed && detail.NotAfter != "" {
		if t, err := time.Parse(time.RFC3339, detail.NotAfter); err == nil {
			expiresAt = &t
		}
	}
	status := detail.Source
	if status == "" {
		status = "none"
	}
	if err := a.store.updateSiteSSL(serverID, site.ID, status, detail.Issuer, expiresAt); err != nil {
		return nil, fmt.Errorf("ssl status fetched but could not be recorded: %w", err)
	}
	return &detail, nil
}

// handleGetSSLStatus is the dashboard's poll target for a site's
// certificate — always re-checks the agent rather than only returning the
// last-persisted row, since a certificate can expire or a renewal can
// fail entirely outside of any dashboard action.
func (a *apiServer) handleGetSSLStatus(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	detail, err := a.persistSSLStatus(ctx, serverID, actor, site)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// handleIssueSSL requests a Let's Encrypt certificate for a site's primary
// domain. Only the domain already recorded on the site is ever used —
// there is no free-form domain field here, so this can't be pointed at a
// domain the caller doesn't control a site for on this server.
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
		writeErr(w, http.StatusUnprocessableEntity, "certificate issuance failed on the agent: "+ev.Message)
		return
	}
	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s", siteID, site.Domain))

	detail, err := a.persistSSLStatus(ctx, serverID, actor, site)
	if err != nil {
		// The certificate was issued successfully; only the follow-up
		// status refresh failed. Report success with a stale/unknown
		// status rather than telling the caller issuance itself failed.
		writeJSON(w, http.StatusCreated, map[string]string{"status": "issued", "warning": "issued, but status could not be refreshed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, detail)
}

// handleInstallCustomSSL installs a caller-supplied certificate/key pair.
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
		writeErr(w, http.StatusUnprocessableEntity, "custom certificate installation failed on the agent: "+ev.Message)
		return
	}
	a.store.log(serverID, actor, "ssl.custom_installed", fmt.Sprintf("site_id=%s domain=%s", siteID, site.Domain))

	detail, err := a.persistSSLStatus(ctx, serverID, actor, site)
	if err != nil {
		writeJSON(w, http.StatusCreated, map[string]string{"status": "installed", "warning": "installed, but status could not be refreshed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, detail)
}

// handleRenewSSL force-renews the site's current Let's Encrypt
// certificate ahead of schedule.
func (a *apiServer) handleRenewSSL(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLRenew, map[string]any{"domain": site.Domain})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "ssl.renew_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "renewal failed on the agent: "+ev.Message)
		return
	}
	a.store.log(serverID, actor, "ssl.renewed", fmt.Sprintf("site_id=%s domain=%s", siteID, site.Domain))

	detail, err := a.persistSSLStatus(ctx, serverID, actor, site)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "renewed", "warning": "renewed, but status could not be refreshed: " + err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, detail)
}

// handleUninstallSSL removes the site's certificate and reverts its vhost
// to plain HTTP. Site metadata needed to regenerate the vhost (system
// user, temp domain, docroot, app type, PHP version) is not accepted from
// the request body — only what's already recorded for this site is ever
// sent to the agent, so this can't be used to rewrite an unrelated site's
// vhost.
func (a *apiServer) handleUninstallSSL(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLUninstall, map[string]any{
		"domain": site.Domain, "system_user": site.SystemUser, "docroot": site.Docroot,
		"app_type": site.AppType, "php_version": site.PHPVersion,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "ssl.uninstall_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "SSL removal failed on the agent: "+ev.Message)
		return
	}
	if err := a.store.updateSiteSSL(serverID, siteID, "none", "", nil); err != nil {
		writeErr(w, http.StatusInternalServerError, "SSL removed on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.uninstalled", fmt.Sprintf("site_id=%s domain=%s", siteID, site.Domain))
	writeJSON(w, http.StatusOK, map[string]string{"status": "none"})
}
