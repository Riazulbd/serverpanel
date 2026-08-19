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
}

func TestGetSiteIsScopedToServerID(t *testing.T) {
	st := newTestStore(t)
	serverA, _, _ := st.createServer("web-a", "", nil, time.Hour, "admin@example.com")
	serverB, _, _ := st.createServer("web-b", "", nil, time.Hour, "admin@example.com")
	site, err := st.createSite(serverA, "a.example.com", "sp_a", "/home/sites/sp_a", "static", "")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	if _, ok := st.getSite(serverA, site.ID); !ok {
		t.Fatal("expected getSite to find the site under its real server")
	}
	if _, ok := st.getSite(serverB, site.ID); ok {
		t.Fatal("expected getSite to refuse a site ID under the wrong server")
	}
}

func TestBackupCreateListGetRoundTrip(t *testing.T) {
	st := newTestStore(t)
	serverID, _, _ := st.createServer("web-7", "", nil, time.Hour, "admin@example.com")
	site, err := st.createSite(serverID, "b.example.com", "sp_b", "/home/sites/sp_b", "wordpress", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	backup, err := st.createBackup(serverID, site.ID, "full", "/var/backups/serverpanel/b-full-1.tar.gz", "wpdb", 12345, "deadbeef")
	if err != nil {
		t.Fatalf("createBackup: %v", err)
	}
	if backup.ID == "" || backup.Status != "complete" {
		t.Fatalf("unexpected backup record: %+v", backup)
	}

	list := st.listBackups(serverID, site.ID)
	if len(list) != 1 || list[0].Path != backup.Path {
		t.Fatalf("listBackups = %+v, want one entry matching the created backup", list)
	}

	got, ok := st.getBackup(serverID, backup.ID)
	if !ok {
		t.Fatal("expected getBackup to find the created backup")
	}
	if got.DBName != "wpdb" || got.SHA256 != "deadbeef" {
		t.Fatalf("getBackup = %+v, fields don't round-trip", got)
	}

	otherServer, _, _ := st.createServer("web-8", "", nil, time.Hour, "admin@example.com")
	if _, ok := st.getBackup(otherServer, backup.ID); ok {
		t.Fatal("expected getBackup to refuse a backup ID under the wrong server")
	}
}

func TestDatabaseCreateListGetDeleteRoundTrip(t *testing.T) {
	st := newTestStore(t)
	serverID, _, _ := st.createServer("web-11", "", nil, time.Hour, "admin@example.com")
	site, err := st.createSite(serverID, "d.example.com", "sp_d", "/home/sites/sp_d", "wordpress", "8.3")
	if err != nil {
		t.Fatalf("createSite: %v", err)
	}

	rec, err := st.createDatabase(serverID, site.ID, "wpdb", "wpdb_owner")
	if err != nil {
		t.Fatalf("createDatabase: %v", err)
	}
	if rec.ID == "" || rec.Status != "active" {
		t.Fatalf("unexpected database record: %+v", rec)
	}

	list := st.listDatabases(serverID)
	if len(list) != 1 || list[0].Name != "wpdb" {
		t.Fatalf("listDatabases = %+v, want one entry matching the created database", list)
	}

	got, ok := st.getDatabase(serverID, rec.ID)
	if !ok {
		t.Fatal("expected getDatabase to find the created database")
	}
	if got.OwnerUser != "wpdb_owner" || got.SiteID != site.ID {
		t.Fatalf("getDatabase = %+v, fields don't round-trip", got)
	}

	otherServer, _, _ := st.createServer("web-12", "", nil, time.Hour, "admin@example.com")
	if _, ok := st.getDatabase(otherServer, rec.ID); ok {
		t.Fatal("expected getDatabase to refuse a database ID under the wrong server")
	}
	if err := st.deleteDatabaseRecord(otherServer, rec.ID); err == nil {
		t.Fatal("expected deleteDatabaseRecord to refuse a database ID under the wrong server")
	}

	if err := st.deleteDatabaseRecord(serverID, rec.ID); err != nil {
		t.Fatalf("deleteDatabaseRecord: %v", err)
	}
	if list := st.listDatabases(serverID); len(list) != 0 {
		t.Fatalf("listDatabases after delete = %+v, want empty", list)
	}
}

func TestCreateDatabaseRejectsDuplicateName(t *testing.T) {
	st := newTestStore(t)
	serverID, _, _ := st.createServer("web-13", "", nil, time.Hour, "admin@example.com")

	if _, err := st.createDatabase(serverID, "", "dupdb", "dupdb_owner"); err != nil {
		t.Fatalf("first createDatabase: %v", err)
	}
	if _, err := st.createDatabase(serverID, "", "dupdb", "another_owner"); err == nil {
		t.Fatal("expected createDatabase to reject a duplicate name on the same server")
	}
}

func TestGenerateSecurePasswordIsLongAndRandom(t *testing.T) {
	p1, err := generateSecurePassword()
	if err != nil {
		t.Fatalf("generateSecurePassword: %v", err)
	}
	p2, err := generateSecurePassword()
	if err != nil {
		t.Fatalf("generateSecurePassword: %v", err)
	}
	if len(p1) < 16 {
		t.Fatalf("generated password too short for db.create's owner_password requirement: %d chars", len(p1))
	}
	if p1 == p2 {
		t.Fatal("expected two generated passwords to differ")
	}
}
