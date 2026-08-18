package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleIssueSSL dispatches ssl.issue_letsencrypt for a site's domain and,
// only on success, follows up with ssl.renewal_status to learn the real
// expiry date certbot just set — the issue call itself only ever returns a
// plain confirmation string, not a parseable expiry, and a dashboard
// showing "SSL: active" with no expiry date is not enough to catch the
// renewal-stops-working failure mode APP-016 exists to close.
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
	json.NewDecoder(r.Body).Decode(&req)
	email := req.Email
	if email == "" {
		email = actor // the requesting account's own login email is a sane default for Let's Encrypt expiry/urgent notices
	}

	// certbot's ACME handshake plus an nginx reload comfortably exceeds
	// most quick-dispatch timeouts; give it the same budget backups get.
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
		a.store.log(serverID, actor, "ssl.issue_failed", "site_id="+siteID+" domain="+site.Domain+": "+ev.Message)
		writeErr(w, http.StatusUnprocessableEntity, "ssl.issue_letsencrypt failed on the agent: "+ev.Message)
		return
	}

	status, expiresAt := "active", ""
	if statusEv, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLRenewalStatus, nil); err == nil && statusEv.Status == proto.TaskSucceeded {
		expiresAt = expiryForDomain(statusEv.Detail, site.Domain)
	}
	if err := a.store.updateSiteSSL(serverID, siteID, status, expiresAt); err != nil {
		writeErr(w, http.StatusInternalServerError, "certificate was issued on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "ssl.issued", "site_id="+siteID+" domain="+site.Domain+" expires_at="+expiresAt)

	writeJSON(w, http.StatusOK, map[string]any{
		"domain": site.Domain, "ssl_status": status, "ssl_expires_at": expiresAt,
	})
}

// handleSSLStatus queries the agent live for every certificate it manages
// (not just this one site's) and, when this site's domain is among them,
// refreshes the persisted status to match — so a cert that stopped
// renewing shows up as such the next time anyone checks, not only right
// after issuance.
func (a *apiServer) handleSSLStatus(w http.ResponseWriter, r *http.Request) {
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

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapSSLRenewalStatus, nil)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "ssl.renewal_status failed on the agent: "+ev.Message)
		return
	}

	expiresAt := expiryForDomain(ev.Detail, site.Domain)
	if expiresAt != "" && expiresAt != site.SSLExpiresAt {
		a.store.updateSiteSSL(serverID, siteID, "active", expiresAt)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(ev.Detail))
}

// expiryForDomain picks this site's certificate out of a
// ssl.renewal_status result (which reports every certificate on the host,
// not just one site's) by exact domain match, returning "" if the domain
// isn't among the certificates certbot currently manages.
func expiryForDomain(renewalStatusJSON, domain string) string {
	var result struct {
		Certificates []struct {
			Domain    string `json:"domain"`
			ExpiresAt string `json:"expires_at"`
		} `json:"certificates"`
	}
	if err := json.Unmarshal([]byte(renewalStatusJSON), &result); err != nil {
		return ""
	}
	for _, c := range result.Certificates {
		if c.Domain == domain {
			return c.ExpiresAt
		}
	}
	return ""
}
