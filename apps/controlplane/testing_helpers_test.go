package main

import (
	"path/filepath"
	"testing"
	"time"
)

// newTestStore returns a store backed by a fresh temp-file SQLite database
// with the schema applied, torn down automatically at test end. A temp file
// (rather than ":memory:") matches openDB's real code path exactly, since
// openDB appends pragma query params to whatever path it's given.
func newTestStore(t *testing.T) *store {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := openDB(dbPath)
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return newStore(db)
}

// newTestAPIServer wires up a full apiServer (store, real in-process CA,
// gateway) against a temp DB/CA dir, matching how main.go constructs one,
// so http_test.go exercises the real routes() mux end-to-end.
func newTestAPIServer(t *testing.T) *apiServer {
	t.Helper()
	st := newTestStore(t)
	dir := t.TempDir()
	ca, err := loadOrCreateAgentCA(filepath.Join(dir, "ca-cert.pem"), filepath.Join(dir, "ca-key.pem"), 1)
	if err != nil {
		t.Fatalf("loadOrCreateAgentCA: %v", err)
	}
	gw := newGateway(ca, st)
	secrets, err := loadOrCreateSecretKey(filepath.Join(dir, "secrets.key"))
	if err != nil {
		t.Fatalf("loadOrCreateSecretKey: %v", err)
	}
	return &apiServer{store: st, ca: ca, gw: gw, gatewayAddr: "127.0.0.1:0", tokenTTL: 15 * time.Minute, secrets: secrets}
}
