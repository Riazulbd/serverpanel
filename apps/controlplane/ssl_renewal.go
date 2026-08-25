package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// sslRenewalActor is the audit-log actor recorded for renewals the
// scheduler performs on its own, so a real administrator's actions
// (ssl.issued, ssl.custom_installed, ...) are never confused with an
// unattended background check in the audit trail.
const sslRenewalActor = "system:ssl-renewal"

// runSSLRenewalLoop periodically attempts to renew every site's Let's
// Encrypt certificate, mirroring what certbot's own systemd timer does on
// a single host — except here the control plane has to reach out to N
// agents instead of renewing locally. It runs until ctx is cancelled.
func (a *apiServer) runSSLRenewalLoop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.renewDueSSLCertificates(ctx)
		}
	}
}

// renewDueSSLCertificates dispatches ssl.renew for every site this control
// plane has ever recorded a Let's Encrypt certificate for. certbot itself
// decides whether each one is actually due (see ssl.renew's doc comment in
// packages/capabilities/ssl.go), so this runs unconditionally on every
// tick rather than duplicating that decision here. A site whose server
// isn't currently connected, or whose renewal attempt fails, is logged and
// skipped — one offline or misbehaving server never stops the rest of the
// fleet from being checked.
func (a *apiServer) renewDueSSLCertificates(ctx context.Context) {
	for _, site := range a.store.listSitesWithIssuer("letsencrypt") {
		a.renewOneSSLCertificate(ctx, site)
	}
}

func (a *apiServer) renewOneSSLCertificate(ctx context.Context, site *siteRecord) {
	taskCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(taskCtx, site.ServerID, sslRenewalActor, capabilities.CapSSLRenew,
		map[string]any{"domain": site.Domain})
	if err != nil {
		// Most commonly "server is not currently connected" — expected
		// for an offline agent, not worth cluttering the persistent
		// audit log with every tick.
		log.Printf("ssl renewal: server %s site %s (%s): %v", site.ServerID, site.ID, site.Domain, err)
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(site.ServerID, sslRenewalActor, "ssl.renew_failed",
			fmt.Sprintf("site_id=%s domain=%s: %s", site.ID, site.Domain, ev.Message))
		return
	}

	res, err := a.recordSSLResult(site.ServerID, site.ID, ev)
	if err != nil {
		log.Printf("ssl renewal: server %s site %s (%s): %v", site.ServerID, site.ID, site.Domain, err)
		return
	}
	a.store.log(site.ServerID, sslRenewalActor, "ssl.renew_checked",
		fmt.Sprintf("site_id=%s domain=%s expires_at=%s days_remaining=%d", site.ID, site.Domain, res.ExpiresAt, res.DaysRemaining))
}
