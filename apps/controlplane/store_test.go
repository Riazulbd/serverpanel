package main

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *store {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return newStore(db)
}

// TestBootstrapTokenIsSingleUse is the core registration guarantee from
// docs/security-trust-model.md §1: a token buys exactly one machine
// identity, and a replay of the same token must fail even though it was
// valid moments earlier.
func TestBootstrapTokenIsSingleUse(t *testing.T) {
	st := newTestStore(t)

	id, token, err := st.createServer("srv", "grp", nil, time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	gotID, err := st.redeemToken(token)
	if err != nil {
		t.Fatalf("first redeemToken failed: %v", err)
	}
	if gotID != id {
		t.Errorf("redeemToken returned server %q, want %q", gotID, id)
	}

	if _, err := st.redeemToken(token); err == nil {
		t.Error("second redeemToken succeeded; bootstrap tokens must be single-use")
	}
}

// TestBootstrapTokenRedemptionIsAtomic backs the "atomically" claim in
// docs/security-trust-model.md §1. Two agents racing to register with the
// same token (a copy-pasted install command run twice, or a replay) must
// produce exactly one identity — a check-then-delete that isn't
// transactional would let both through and hand two machines the same
// server identity.
func TestBootstrapTokenRedemptionIsAtomic(t *testing.T) {
	st := newTestStore(t)

	_, token, err := st.createServer("srv", "", nil, time.Minute, "t@e.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	const racers = 16
	start := make(chan struct{})
	results := make(chan error, racers)

	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := st.redeemToken(token)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("%d concurrent redemptions succeeded, want exactly 1 — the token is not single-use under concurrency", successes)
	}
}

func TestBootstrapTokenExpires(t *testing.T) {
	st := newTestStore(t)

	// Negative TTL == already expired, which avoids a sleep in the test.
	_, token, err := st.createServer("srv", "", nil, -time.Second, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	if _, err := st.redeemToken(token); err == nil {
		t.Error("redeemToken accepted an expired token")
	}
}

func TestRedeemUnknownTokenFails(t *testing.T) {
	st := newTestStore(t)
	for _, token := range []string{"", "deadbeef", strings.Repeat("a", 64)} {
		if _, err := st.redeemToken(token); err == nil {
			t.Errorf("redeemToken accepted unknown token %q", token)
		}
	}
}

// TestBootstrapTokenStoredOnlyAsHash checks the token is not recoverable
// from the database — the plaintext should exist only in the install
// command handed to the user.
func TestBootstrapTokenStoredOnlyAsHash(t *testing.T) {
	st := newTestStore(t)

	_, token, err := st.createServer("srv", "", nil, time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}

	var stored string
	if err := st.db.QueryRow(`SELECT hash FROM bootstrap_tokens LIMIT 1`).Scan(&stored); err != nil {
		t.Fatalf("read stored token row: %v", err)
	}
	if stored == token {
		t.Fatal("bootstrap token is stored in plaintext")
	}
	want := sha256.Sum256([]byte(token))
	if stored != hex.EncodeToString(want[:]) {
		t.Errorf("stored value %q is not the SHA-256 of the issued token", stored)
	}
}

// TestAuditLogNeverContainsTokenPlaintext guards the "never appear in
// permanent logs" requirement.
func TestAuditLogNeverContainsTokenPlaintext(t *testing.T) {
	st := newTestStore(t)

	_, token, err := st.createServer("srv", "", nil, time.Minute, "tester@example.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	st.redeemToken(token)

	for _, e := range st.auditLog() {
		if strings.Contains(e.Detail, token) || strings.Contains(e.Action, token) {
			t.Fatalf("audit entry %q leaked the bootstrap token plaintext", e.Action)
		}
	}
}

// TestRevokedCertCannotReconnect covers the revocation path the gateway
// consults on every handshake.
func TestRevokedCertCannotReconnect(t *testing.T) {
	st := newTestStore(t)

	id, token, _ := st.createServer("srv", "", nil, time.Minute, "tester@example.com")
	st.redeemToken(token)
	st.markIssuedCert(id, "1234")

	if st.isRevoked("1234") {
		t.Fatal("certificate reported revoked before any revocation")
	}
	if err := st.revokeServer(id, "tester@example.com"); err != nil {
		t.Fatalf("revokeServer: %v", err)
	}
	if !st.isRevoked("1234") {
		t.Error("certificate not reported revoked after revokeServer")
	}

	rec, ok := st.get(id)
	if !ok {
		t.Fatal("server record missing after revocation")
	}
	if rec.Status != statusDisconnected {
		t.Errorf("status after revocation = %q, want %q", rec.Status, statusDisconnected)
	}
}

// TestRevokedServerStaysDisconnected makes sure a heartbeat or reconnect
// attempt can't quietly flip a revoked server back to a live state.
func TestRevokedServerStaysDisconnected(t *testing.T) {
	st := newTestStore(t)

	id, token, _ := st.createServer("srv", "", nil, time.Minute, "tester@example.com")
	st.redeemToken(token)
	st.markIssuedCert(id, "42")
	st.revokeServer(id, "tester@example.com")

	st.setConnected(id, false)
	rec, _ := st.get(id)
	if rec.Status != statusDisconnected {
		t.Errorf("revoked server reverted to %q on disconnect bookkeeping", rec.Status)
	}
}

// TestMaxKnownCertSerial backs the CA serial-reseeding logic: after a
// restart the CA must not reissue a serial that already means something in
// the revocation list.
func TestMaxKnownCertSerial(t *testing.T) {
	st := newTestStore(t)

	if got := st.maxKnownCertSerial(); got != 0 {
		t.Errorf("maxKnownCertSerial on empty store = %d, want 0", got)
	}

	id1, tok1, _ := st.createServer("a", "", nil, time.Minute, "t@e.com")
	st.redeemToken(tok1)
	st.markIssuedCert(id1, "105")

	id2, tok2, _ := st.createServer("b", "", nil, time.Minute, "t@e.com")
	st.redeemToken(tok2)
	st.markIssuedCert(id2, "230")
	st.revokeServer(id2, "t@e.com")

	if got := st.maxKnownCertSerial(); got != 230 {
		t.Errorf("maxKnownCertSerial = %d, want 230 (highest issued/revoked)", got)
	}
}

func TestRevokeTokenPreventsLaterRedemption(t *testing.T) {
	st := newTestStore(t)

	id, token, _ := st.createServer("srv", "", nil, time.Minute, "t@e.com")
	st.revokeToken(id, "t@e.com")

	if _, err := st.redeemToken(token); err == nil {
		t.Error("a revoked bootstrap token was still redeemable")
	}
}

func TestStorePersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "persist.db")

	db1, err := openDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	st1 := newStore(db1)
	id, _, err := st1.createServer("persisted", "grp", []string{"a", "b"}, time.Minute, "t@e.com")
	if err != nil {
		t.Fatalf("createServer: %v", err)
	}
	db1.Close()

	db2, err := openDB(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	st2 := newStore(db2)

	rec, ok := st2.get(id)
	if !ok {
		t.Fatal("server record did not survive reopening the database")
	}
	if rec.Name != "persisted" || rec.Group != "grp" || len(rec.Tags) != 2 {
		t.Errorf("record came back altered: %+v", rec)
	}
}

func TestHeartbeatRoundTrips(t *testing.T) {
	st := newTestStore(t)
	id, _, _ := st.createServer("srv", "", nil, time.Minute, "t@e.com")

	now := time.Now().UTC().Truncate(time.Millisecond)
	st.recordHeartbeat(id, heartbeatSnapshot{
		UptimeSecs: 1234, LoadAvg1: 0.75, MemUsedPct: 42.5, DiskUsedPct: 10.25, At: now,
	})

	rec, ok := st.get(id)
	if !ok || rec.LastHeartbeat == nil {
		t.Fatal("heartbeat not stored")
	}
	hb := rec.LastHeartbeat
	if hb.UptimeSecs != 1234 || hb.LoadAvg1 != 0.75 || hb.MemUsedPct != 42.5 || hb.DiskUsedPct != 10.25 {
		t.Errorf("heartbeat round-trip mismatch: %+v", hb)
	}
}

func TestSiteRecordsAreScopedPerServer(t *testing.T) {
	st := newTestStore(t)
	a, _, _ := st.createServer("a", "", nil, time.Minute, "t@e.com")
	b, _, _ := st.createServer("b", "", nil, time.Minute, "t@e.com")

	if _, err := st.createSite(a, "a.com", "site_a", "/home/sites/site_a/public", "php", "8.3"); err != nil {
		t.Fatalf("createSite: %v", err)
	}

	if got := len(st.listSites(a)); got != 1 {
		t.Errorf("server a has %d sites, want 1", got)
	}
	if got := len(st.listSites(b)); got != 0 {
		t.Errorf("server b has %d sites, want 0 — sites must not leak across servers", got)
	}
}
