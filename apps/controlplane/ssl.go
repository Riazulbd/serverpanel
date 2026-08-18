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

// handleIssueLetsEncryptSSL dispatches ssl.issue_letsencrypt for a site's
// domain, using the authenticated caller's own account email for Let's
// Encrypt's expiry/urgent-renewal notices, then refreshes the certificate's
// recorded expiry the same way handleGetSSLStatus does — a successful issue
// call always leaves ssl_certificates in sync, never relying on a separate
// manual refresh.
func (a *apiServer) handleIssueLetsEncryptSSL(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	// certbot itself can take well over a minute for a fresh domain
	// (ACME challenge round trip + nginx reload); the default dispatch
	// timeout is too tight.
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLIssueLE, map[string]any{
		"domain": site.Domain, "email": actor,
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

	cert, err := a.refreshSSLStatus(r.Context(), serverID, siteID, site.Domain, actor)
	if err != nil {
		// The certificate is real and live on the server even if this
		// control-plane bookkeeping call failed — report success with a
		// warning rather than a false failure that would prompt a
		// needless re-issue.
		a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s (status refresh failed: %v)", siteID, site.Domain, err))
		writeJSON(w, http.StatusCreated, map[string]any{"domain": site.Domain, "warning": "issued, but could not refresh recorded expiry: " + err.Error()})
		return
	}

	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s expires_at=%s", siteID, site.Domain, cert.ExpiresAt.Format(time.RFC3339)))
	writeJSON(w, http.StatusCreated, cert)
}

// handleInstallCustomSSL dispatches ssl.install_custom with a caller-supplied
// certificate/key pair and records its expiry the same way issuance does.
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
		writeErr(w, http.StatusUnprocessableEntity, "custom certificate install failed on the agent: "+ev.Message)
		return
	}

	cert, err := a.refreshSSLStatus(r.Context(), serverID, siteID, site.Domain, actor)
	if err != nil {
		a.store.log(serverID, actor, "ssl.custom_installed", fmt.Sprintf("site_id=%s domain=%s (status refresh failed: %v)", siteID, site.Domain, err))
		writeJSON(w, http.StatusCreated, map[string]any{"domain": site.Domain, "warning": "installed, but could not refresh recorded expiry: " + err.Error()})
		return
	}

	a.store.log(serverID, actor, "ssl.custom_installed", fmt.Sprintf("site_id=%s domain=%s expires_at=%s", siteID, site.Domain, cert.ExpiresAt.Format(time.RFC3339)))
	writeJSON(w, http.StatusCreated, cert)
}

// handleGetSSLStatus dispatches ssl.status live (rather than only reading
// the cached ssl_certificates row) so the dashboard always reflects what's
// actually on disk — e.g. after certbot's own renewal timer silently
// replaces a certificate outside of any control-plane-initiated call — and
// persists the refreshed result as a side effect.
func (a *apiServer) handleGetSSLStatus(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	cert, err := a.refreshSSLStatus(r.Context(), serverID, siteID, site.Domain, actor)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if cert == nil {
		writeJSON(w, http.StatusOK, map[string]any{"domain": site.Domain, "installed": false})
		return
	}
	writeJSON(w, http.StatusOK, cert)
}

// refreshSSLStatus dispatches ssl.status for one domain and, if a
// certificate is currently installed for it, upserts the recorded expiry.
// Returns (nil, nil) — not an error — when no certificate exists yet, since
// "no SSL installed" is an expected, valid state for a freshly created site.
func (a *apiServer) refreshSSLStatus(ctx context.Context, serverID, siteID, domain, actor string) (*sslCertificateRecord, error) {
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(dctx, serverID, actor, capabilities.CapSSLStatus, map[string]any{"domain": domain})
	if err != nil {
		return nil, err
	}
	if ev.Status != proto.TaskSucceeded {
		return nil, fmt.Errorf("ssl.status failed on the agent: %s", ev.Message)
	}

	var statuses []struct {
		Domain    string `json:"domain"`
		Issuer    string `json:"issuer"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &statuses); err != nil {
		return nil, fmt.Errorf("parse ssl.status result: %w", err)
	}
	if len(statuses) == 0 {
		return nil, nil
	}

	expiresAt, err := time.Parse(time.RFC3339, statuses[0].ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("parse certificate expiry: %w", err)
	}
	return a.store.upsertSSLCertificate(serverID, siteID, domain, statuses[0].Issuer, expiresAt)
}
