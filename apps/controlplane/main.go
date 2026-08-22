// Command controlplane runs the ServerPanel control plane: the public HTTP
// API (browser-facing, plain TLS) and the agent gateway (mTLS-only,
// agent-facing) described in docs/architecture.md. For Phase 1 development
// both listeners run in a single process sharing one SQLite-backed store;
// the two are already structured as separate components (apiServer,
// gateway) so they can be split into separately deployable services,
// backed by Postgres, without changing the protocol between them.
package main

import (
	"flag"
	"log"
	"net/http"
	"path/filepath"
	"time"
)

func main() {
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "public HTTP API listen address")
	gatewayAddr := flag.String("gateway-addr", "127.0.0.1:8843", "agent mTLS gateway listen address")
	gatewayPublic := flag.String("gateway-public-addr", "", "gateway address advertised to agents (defaults to -gateway-addr)")
	tokenTTL := flag.Duration("bootstrap-token-ttl", 15*time.Minute, "how long a registration bootstrap token remains valid")
	dbPath := flag.String("db", "serverpanel.db", "path to the SQLite database file")
	caDir := flag.String("ca-dir", "", "directory to persist the internal agent CA's cert/key (defaults next to -db)")
	publicDir := flag.String("public-dir", "", "directory of static dashboard assets to serve (defaults to apps/controlplane/web relative to the binary's working dir)")
	insecureCookies := flag.Bool("insecure-cookies", false, "allow session cookies over plain HTTP (local development only, never in production)")
	flag.Parse()

	if *gatewayPublic == "" {
		*gatewayPublic = *gatewayAddr
	}
	if *insecureCookies {
		secureCookies = false
		log.Println("WARNING: -insecure-cookies is set; session cookies will be sent over plain HTTP. Do not use in production.")
	}

	db, err := openDB(*dbPath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer db.Close()
	st := newStore(db)

	if *caDir == "" {
		*caDir = filepath.Dir(*dbPath)
	}
	ca, err := loadOrCreateAgentCA(
		filepath.Join(*caDir, "agent-ca-cert.pem"),
		filepath.Join(*caDir, "agent-ca-key.pem"),
		st.maxKnownCertSerial()+1,
	)
	if err != nil {
		log.Fatalf("initialize agent CA: %v", err)
	}
	gw := newGateway(ca, st)

	secretKey, err := loadOrCreateSecretKey(filepath.Join(*caDir, "secret-key.bin"))
	if err != nil {
		log.Fatalf("initialize secret key: %v", err)
	}
	secrets, err := newSecretBox(secretKey)
	if err != nil {
		log.Fatalf("initialize secret box: %v", err)
	}

	go func() {
		if err := gw.listenAndServe(*gatewayAddr); err != nil {
			log.Fatalf("agent gateway: %v", err)
		}
	}()

	api := &apiServer{store: st, ca: ca, gw: gw, secrets: secrets, gatewayAddr: *gatewayPublic, tokenTTL: *tokenTTL, publicDir: *publicDir}
	log.Printf("public API listening on %s (db: %s)", *apiAddr, *dbPath)
	if err := http.ListenAndServe(*apiAddr, api.routes()); err != nil {
		log.Fatalf("public API: %v", err)
	}
}
