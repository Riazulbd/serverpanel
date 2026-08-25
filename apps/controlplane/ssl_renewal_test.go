package main

import (
	"context"
	"testing"
	"time"
)

// TestRenewDueSSLCertificatesSkipsDisconnectedServersWithoutError proves
// the scheduler's core safety property: a site whose server has no
// connected agent must not stop the sweep, panic, or corrupt that site's
// stored SSL state. This is the common case in practice (most agents are
// only intermittently connected between renewal ticks).
func TestRenewDueSSLCertificatesSkipsDisconnectedServersWithoutError(t *testing.T) {
	a := newTestAPIServer(t)

	serverID, _, err := a.store.createServer("renew-1", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	site, err := a.store.createSite(serverID, "renew.example.com", "sp_renew", "/home/sites/sp_renew", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}
	if err := a.store.updateSiteSSL(serverID, site.ID, "letsencrypt", "2030-01-01T00:00:00Z"); err != nil {
		t.Fatalf("updateSiteSSL: %v", err)
	}

	// No agent is connected in this test, so this must complete without
	// panicking or blocking, and must leave the recorded expiry
	// untouched (a failed dispatch is never mistaken for "no certificate").
	a.renewDueSSLCertificates(context.Background())

	got, ok := a.store.getSite(serverID, site.ID)
	if !ok {
		t.Fatal("getSite: not found")
	}
	if got.SSLIssuer != "letsencrypt" || got.SSLExpiresAt != "2030-01-01T00:00:00Z" {
		t.Fatalf("a failed renewal attempt must not overwrite the last-known SSL state, got %+v", got)
	}
}

// TestRenewDueSSLCertificatesIgnoresNonLetsEncryptSites proves the
// scheduler never touches custom-installed certificates — certbot has no
// concept of renewing something it didn't issue.
func TestRenewDueSSLCertificatesIgnoresNonLetsEncryptSites(t *testing.T) {
	a := newTestAPIServer(t)

	serverID, _, err := a.store.createServer("renew-2", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	site, err := a.store.createSite(serverID, "custom-renew.example.com", "sp_cr", "/home/sites/sp_cr", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}
	if err := a.store.updateSiteSSL(serverID, site.ID, "custom", "2030-01-01T00:00:00Z"); err != nil {
		t.Fatalf("updateSiteSSL: %v", err)
	}

	before, _ := a.store.getSite(serverID, site.ID)
	a.renewDueSSLCertificates(context.Background())
	after, _ := a.store.getSite(serverID, site.ID)

	if before.SSLCheckedAt != after.SSLCheckedAt {
		t.Fatalf("scheduler touched a custom-issued site's SSL state: before=%+v after=%+v", before, after)
	}
}
