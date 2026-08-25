package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// sslIssueResult mirrors packages/capabilities.sslResult's JSON shape —
// kept as a local, narrow copy rather than importing the capabilities
// package's internal type, since the wire contract (what ssl.* capability
// details look like) is what the control plane actually depends on, not
// the agent's internal representation.
type sslIssueResult struct {
	Domain    string `json:"domain"`
	Source    string `json:"source"`
	ExpiresAt string `json:"expires_at"`
	Issuer    string `json:"issuer"`
}

// handleIssueLetsEncrypt dispatches ssl.issue_letsencrypt for a site's
// domain and, on success, records the resulting certificate status/expiry
// against the site — the same dispatch-then-persist-on-success pattern
// handleCreateSite and handleCreateBackup use.
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		writeErr(w, http.StatusBadRequest, "email is required")
		return
	}

	// certbot's ACME handshake plus an nginx reload comfortably exceeds the
	// generic dispatch default; issuing a cert gets its own longer budget,
	// matching backups/restores.
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
		a.store.updateSiteSSL(serverID, siteID, "error", "", ev.Message)
		a.store.log(serverID, actor, "ssl.issue_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "ssl.issue_letsencrypt failed on the agent: "+ev.Message)
		return
	}

	var result sslIssueResult
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued on the agent but its result could not be parsed: "+err.Error())
		return
	}
	if err := a.store.updateSiteSSL(serverID, siteID, "active", result.ExpiresAt, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.issued", fmt.Sprintf("site_id=%s domain=%s source=letsencrypt expires_at=%s", siteID, site.Domain, result.ExpiresAt))

	writeJSON(w, http.StatusOK, result)
}

// handleInstallCustomSSL dispatches ssl.install_custom for a site's domain.
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
		a.store.updateSiteSSL(serverID, siteID, "error", "", ev.Message)
		a.store.log(serverID, actor, "ssl.install_custom_failed", fmt.Sprintf("site_id=%s domain=%s: %s", siteID, site.Domain, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "ssl.install_custom failed on the agent: "+ev.Message)
		return
	}

	var result sslIssueResult
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was installed on the agent but its result could not be parsed: "+err.Error())
		return
	}
	if err := a.store.updateSiteSSL(serverID, siteID, "active", result.ExpiresAt, ""); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was installed but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.installed", fmt.Sprintf("site_id=%s domain=%s source=custom expires_at=%s", siteID, site.Domain, result.ExpiresAt))

	writeJSON(w, http.StatusOK, result)
}

// sslExpiryWarningWindow is how far ahead of a certificate's expiry the
// renewal monitor logs a warning. certbot's own timer renews 30 days before
// expiry (see stack.go's "certbot automatic renewal timer" step), so a
// certificate still this close to expiring means renewal has already
// failed at least once — worth surfacing well before it actually lapses.
const sslExpiryWarningWindow = 14 * 24 * time.Hour

// startSSLExpiryMonitor runs for the lifetime of the process, periodically
// re-checking every site with an active certificate via ssl.status and
// recording what it finds. This is what turns "certbot has an automatic
// renewal timer" into "the control plane actually knows whether renewal is
// still working" — a timer running on the VPS is invisible to the
// dashboard/audit log otherwise, and a renewal that silently starts
// failing (DNS moved, rate-limited, nginx config broke) would otherwise
// only be discovered when the certificate has already expired.
func startSSLExpiryMonitor(ctx context.Context, st *store, gw *gateway, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			checkSSLExpiries(ctx, st, gw)
		}
	}
}

func checkSSLExpiries(ctx context.Context, st *store, gw *gateway) {
	for _, site := range st.sitesWithActiveSSL() {
		reqCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		ev, err := gw.dispatch(reqCtx, site.ServerID, "system:ssl-monitor", capabilities.CapSSLStatus, map[string]any{
			"domain": site.Domain,
		})
		cancel()
		if err != nil {
			// Most commonly: the agent simply isn't connected right now.
			// Not an error worth recording — it'll be checked again next
			// tick once the agent reconnects.
			continue
		}
		if ev.Status != proto.TaskSucceeded {
			log.Printf("ssl expiry monitor: ssl.status failed for site=%s domain=%s: %s", site.ID, site.Domain, ev.Message)
			continue
		}

		var result sslIssueResult
		if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
			continue
		}
		if result.ExpiresAt == "" {
			continue
		}
		if err := st.updateSiteSSL(site.ServerID, site.ID, "active", result.ExpiresAt, ""); err != nil {
			log.Printf("ssl expiry monitor: failed to record refreshed status for site=%s: %v", site.ID, err)
			continue
		}

		expiresAt, err := time.Parse(time.RFC3339, result.ExpiresAt)
		if err != nil {
			continue
		}
		if time.Until(expiresAt) <= sslExpiryWarningWindow {
			st.log(site.ServerID, "system:ssl-monitor", "ssl.expiry_warning",
				fmt.Sprintf("site_id=%s domain=%s expires_at=%s — renewal may have failed, certbot.timer normally renews 30 days before expiry",
					site.ID, site.Domain, result.ExpiresAt))
		}
	}
}
