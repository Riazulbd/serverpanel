package main

import (
	"strings"
	"testing"
	"time"
)

func TestCreateUserRejectsShortPassword(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.createUser("a@example.com", "short"); err == nil {
		t.Fatal("expected error for password under 12 characters, got nil")
	}
}

func TestCreateUserLowercasesEmailAndRejectsDuplicate(t *testing.T) {
	st := newTestStore(t)
	u, err := st.createUser("  Alice@Example.com  ", "correcthorsebattery")
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	if u.Email != "alice@example.com" {
		t.Fatalf("email = %q, want lowercased+trimmed", u.Email)
	}
	if _, err := st.createUser("alice@example.com", "anotherlongpassword"); err == nil {
		t.Fatal("expected duplicate email to be rejected")
	}
	// Lookup should also be case-insensitive.
	if _, err := st.getUserByEmail("ALICE@example.com"); err != nil {
		t.Fatalf("getUserByEmail case-insensitive lookup: %v", err)
	}
}

func TestSessionLifecycle(t *testing.T) {
	st := newTestStore(t)
	u, err := st.createUser("bob@example.com", "correcthorsebattery")
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}

	token, err := st.createSession(u.ID, false)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	sess, err := st.lookupSession(token)
	if err != nil {
		t.Fatalf("lookupSession: %v", err)
	}
	if sess.MFAVerified {
		t.Fatal("freshly created session should not be MFA-verified")
	}

	if err := st.verifySessionMFA(token); err != nil {
		t.Fatalf("verifySessionMFA: %v", err)
	}
	sess, err = st.lookupSession(token)
	if err != nil {
		t.Fatalf("lookupSession after verify: %v", err)
	}
	if !sess.MFAVerified {
		t.Fatal("session should be MFA-verified after verifySessionMFA")
	}

	st.deleteSession(token)
	if _, err := st.lookupSession(token); err == nil {
		t.Fatal("expected lookup of deleted session to fail")
	}
}

func TestLookupSessionRejectsExpired(t *testing.T) {
	st := newTestStore(t)
	u, err := st.createUser("carol@example.com", "correcthorsebattery")
	if err != nil {
		t.Fatalf("createUser: %v", err)
	}
	token, err := st.createSession(u.ID, true)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}
	// Force the session's expiry into the past directly, since createSession
	// always uses the real sessionTTL.
	if _, err := st.db.Exec(`UPDATE sessions SET expires_at = ? WHERE token_hash IS NOT NULL`,
		time.Now().Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("force-expire session: %v", err)
	}
	if _, err := st.lookupSession(token); err == nil {
		t.Fatal("expected expired session lookup to fail")
	}
}

func TestBootstrapTokenIsSingleUse(t *testing.T) {
	st := newTestStore(t)
	id, token, err := st.createServer("web-1", "prod", []string{"lemp"}, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	gotID, err := st.redeemToken(token)
	if err != nil {
		t.Fatalf("redeemToken (first use): %v", err)
	}
	if gotID != id {
		t.Fatalf("redeemToken returned server %q, want %q", gotID, id)
	}

	if _, err := st.redeemToken(token); err == nil {
		t.Fatal("expected second redemption of the same token to fail")
	}
}

func TestBootstrapTokenExpiry(t *testing.T) {
	st := newTestStore(t)
	_, token, err := st.createServer("web-2", "", nil, -time.Minute, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	if _, err := st.redeemToken(token); err == nil {
		t.Fatal("expected redemption of an already-expired token to fail")
	}
}

func TestRedeemTokenRejectsUnknownToken(t *testing.T) {
	st := newTestStore(t)
	if _, err := st.redeemToken("not-a-real-token"); err == nil {
		t.Fatal("expected unknown token to be rejected")
	}
}

func TestRevokeServerBlocksReuseOfCertSerial(t *testing.T) {
	st := newTestStore(t)
	id, _, err := st.createServer("web-3", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(id, "42")

	if st.isRevoked("42") {
		t.Fatal("cert should not be revoked yet")
	}
	if err := st.revokeServer(id, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	if !st.isRevoked("42") {
		t.Fatal("cert serial should be revoked after revokeServer")
	}
	rec, ok := st.get(id)
	if !ok {
		t.Fatal("server should still exist after revocation")
	}
	if rec.Status != statusDisconnected {
		t.Fatalf("status = %q, want %q", rec.Status, statusDisconnected)
	}
}

func TestRevokeServerRejectsUnknownServer(t *testing.T) {
	st := newTestStore(t)
	if err := st.revokeServer("srv_doesnotexist", "admin@example.com"); err == nil {
		t.Fatal("expected revoking an unknown server to fail")
	}
}

func TestSetConnectedPreservesRevokedStatus(t *testing.T) {
	st := newTestStore(t)
	id, _, err := st.createServer("web-4", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.markIssuedCert(id, "7")
	if err := st.revokeServer(id, "admin@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	// A stray disconnect event arriving after revocation must not resurrect
	// the server into "offline" — it stays disconnected until re-registered.
	st.setConnected(id, false)
	rec, _ := st.get(id)
	if rec.Status != statusDisconnected {
		t.Fatalf("status after setConnected(false) on a revoked server = %q, want %q", rec.Status, statusDisconnected)
	}
}

func TestRecordHeartbeatAndList(t *testing.T) {
	st := newTestStore(t)
	id, _, err := st.createServer("web-5", "staging", []string{"a", "b"}, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	hb := heartbeatSnapshot{UptimeSecs: 100, LoadAvg1: 0.5, MemUsedPct: 40.2, DiskUsedPct: 12.5, At: time.Now().UTC()}
	st.recordHeartbeat(id, hb)

	rec, ok := st.get(id)
	if !ok {
		t.Fatal("expected server to exist")
	}
	if rec.LastHeartbeat == nil {
		t.Fatal("expected LastHeartbeat to be populated")
	}
	if rec.LastHeartbeat.MemUsedPct != 40.2 {
		t.Fatalf("MemUsedPct = %v, want 40.2", rec.LastHeartbeat.MemUsedPct)
	}
	if len(rec.Tags) != 2 || rec.Tags[0] != "a" {
		t.Fatalf("Tags = %v, want [a b]", rec.Tags)
	}

	list := st.list()
	found := false
	for _, r := range list {
		if r.ID == id {
			found = true
		}
	}
	if !found {
		t.Fatal("expected created server to appear in list()")
	}
}

func TestAuditLogAppendsEntries(t *testing.T) {
	st := newTestStore(t)
	st.log("srv_1", "admin@example.com", "server.created", `name="x"`)
	entries := st.auditLog()
	if len(entries) == 0 {
		t.Fatal("expected at least one audit entry")
	}
	if entries[0].Action != "server.created" {
		t.Fatalf("most recent entry action = %q, want server.created", entries[0].Action)
	}
	if !strings.Contains(entries[0].Detail, "name=") {
		t.Fatalf("detail = %q, missing expected content", entries[0].Detail)
	}
}

func TestCreateAndListSites(t *testing.T) {
	st := newTestStore(t)
	id, _, err := st.createServer("web-6", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	if _, err := st.createSite(id, "example.sslip.io", "sp_abc123", "/home/sites/sp_abc123/public", "static", ""); err != nil {
		t.Fatalf("createSite: %v", err)
	}
	sites := st.listSites(id)
	if len(sites) != 1 {
		t.Fatalf("listSites returned %d sites, want 1", len(sites))
	}
	if sites[0].Domain != "example.sslip.io" {
		t.Fatalf("domain = %q, want example.sslip.io", sites[0].Domain)
	}
	got, ok := st.getSite(sites[0].ID)
	if !ok || got.Domain != "example.sslip.io" {
		t.Fatalf("getSite(%q) = %+v, %v, want the site just created", sites[0].ID, got, ok)
	}
	if _, ok := st.getSite("site_doesnotexist"); ok {
		t.Fatal("getSite of an unknown ID should report not found")
	}
}

func TestCreateAndListBackups(t *testing.T) {
	st := newTestStore(t)
	id, _, err := st.createServer("web-7", "", nil, time.Hour, "admin@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	site, err := st.createSite(id, "example.sslip.io", "sp_abc123", "/home/sites/sp_abc123/public", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec, err := st.createBackup(id, site.ID, "", "files", "/var/backups/serverpanel/sp_abc123-files-20260101T000000Z.tar.gz", 1024, "deadbeef")
	if err != nil {
		t.Fatalf("createBackup: %v", err)
	}
	if rec.ID == "" || rec.Status != "complete" {
		t.Fatalf("createBackup returned unexpected record: %+v", rec)
	}

	backups := st.listBackups(id)
	if len(backups) != 1 {
		t.Fatalf("listBackups returned %d backups, want 1", len(backups))
	}
	if backups[0].Path != rec.Path || backups[0].SHA256 != "deadbeef" {
		t.Fatalf("listed backup = %+v, want it to match created record %+v", backups[0], rec)
	}

	got, ok := st.getBackup(rec.ID)
	if !ok || got.Path != rec.Path {
		t.Fatalf("getBackup(%q) = %+v, %v, want the backup just created", rec.ID, got, ok)
	}
	if _, ok := st.getBackup("backup_doesnotexist"); ok {
		t.Fatal("getBackup of an unknown ID should report not found")
	}
}
