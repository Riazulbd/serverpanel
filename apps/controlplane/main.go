// Command controlplane runs the ServerPanel control plane: the public HTTP
// API (browser-facing, plain TLS) and the agent gateway (mTLS-only,
// agent-facing) described in docs/architecture.md. For Phase 1 development
// both listeners run in a single process sharing an in-memory store; the
// two are already structured as separate components (apiServer, gateway)
// so they can be split into separately deployable services, backed by
// Postgres, without changing the protocol between them.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	apiAddr := flag.String("api-addr", "127.0.0.1:8080", "public HTTP API listen address")
	gatewayAddr := flag.String("gateway-addr", "127.0.0.1:8843", "agent mTLS gateway listen address")
	gatewayPublic := flag.String("gateway-public-addr", "", "gateway address advertised to agents (defaults to -gateway-addr)")
	tokenTTL := flag.Duration("bootstrap-token-ttl", 15*time.Minute, "how long a registration bootstrap token remains valid")
	flag.Parse()

	if *gatewayPublic == "" {
		*gatewayPublic = *gatewayAddr
	}

	ca, err := newAgentCA()
	if err != nil {
		log.Fatalf("initialize agent CA: %v", err)
	}
	st := newStore()
	gw := newGateway(ca, st)

	go func() {
		if err := gw.listenAndServe(*gatewayAddr); err != nil {
			log.Fatalf("agent gateway: %v", err)
		}
	}()

	api := &apiServer{store: st, ca: ca, gw: gw, gatewayAddr: *gatewayPublic, tokenTTL: *tokenTTL}
	log.Printf("public API listening on %s", *apiAddr)
	if err := http.ListenAndServe(*apiAddr, api.routes()); err != nil {
		log.Fatalf("public API: %v", err)
	}
}
