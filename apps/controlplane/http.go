package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// apiServer is the public-facing HTTP API a browser dashboard (and, later,
// the public API mentioned in the product plan) talks to. It is a distinct
// listener from the mTLS agent gateway (apps/controlplane/gateway.go) — a
// browser session never gets anywhere near the agent-facing port.
//
// NOTE: this skeleton has no session/2FA auth wired in yet (see
// docs/product-plan.md Phase 1 milestone list — that's tracked as separate
// follow-up work); every handler here is otherwise structured the way the
// authenticated version will be, with the store as the single source of
// truth and every mutating action audit-logged.
type apiServer struct {
	store       *store
	ca          *agentCA
	gw          *gateway
	gatewayAddr string
	tokenTTL    time.Duration
}

func (a *apiServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /agents/register", a.handleRegister)
	mux.HandleFunc("POST /api/v1/servers", a.handleCreateServer)
	mux.HandleFunc("GET /api/v1/servers", a.handleListServers)
	mux.HandleFunc("GET /api/v1/servers/{id}", a.handleGetServer)
	mux.HandleFunc("POST /api/v1/servers/{id}/revoke", a.handleRevokeServer)
	mux.HandleFunc("POST /api/v1/servers/{id}/tasks", a.handleDispatchTask)
	mux.HandleFunc("GET /api/v1/audit", a.handleAudit)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// handleRegister is the one-time bootstrap-token-for-certificate exchange.
// It is deliberately the only endpoint an agent can reach before it has a
// client certificate, and it never logs the plaintext token (redeemToken
// only ever sees/hashes it; nothing here writes req.Token anywhere).
func (a *apiServer) handleRegister(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "cannot read body")
		return
	}
	var req struct {
		Token  string `json:"token"`
		CSRPEM string `json:"csr_pem"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}

	serverID, err := a.store.redeemToken(req.Token)
	if err != nil {
		// Deliberately generic message + no token value in logs.
		writeErr(w, http.StatusUnauthorized, "registration token invalid, expired, or already used")
		return
	}

	certPEM, serial, err := a.ca.signAgentCSR([]byte(req.CSRPEM), serverID, 30*24*time.Hour)
	if err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("could not sign certificate: %v", err))
		return
	}
	a.store.markIssuedCert(serverID, serial.String())

	writeJSON(w, http.StatusOK, map[string]string{
		"server_id":    serverID,
		"cert_pem":     string(certPEM),
		"ca_pem":       string(a.ca.CAPEM()),
		"gateway_addr": a.gatewayAddr,
	})
}

func (a *apiServer) handleCreateServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string   `json:"name"`
		Group string   `json:"group"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	id, token, err := a.store.createServer(req.Name, req.Group, req.Tags, a.tokenTTL)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	// The one-time install command the user copies onto a clean Ubuntu
	// 24.04 VPS and runs as root. In production this points at a signed
	// release download; the placeholder host below is illustrative.
	installCmd := fmt.Sprintf(
		"curl -fsSL https://get.serverpanel.example/install.sh | sudo bash -s -- --server=%s --token=%s --api=%s",
		id, token, "https://api.serverpanel.example",
	)

	writeJSON(w, http.StatusCreated, map[string]any{
		"server_id":          id,
		"install_command":    installCmd,
		"token_expires_in_s": int(a.tokenTTL.Seconds()),
	})
}

func (a *apiServer) handleListServers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.list())
}

func (a *apiServer) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rec, ok := a.store.get(id)
	if !ok {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (a *apiServer) handleRevokeServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := a.store.revokeServer(id); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	a.store.revokeToken(id)
	a.gw.forceDisconnect(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (a *apiServer) handleDispatchTask(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Capability string         `json:"capability"`
		Params     map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Capability == "" {
		writeErr(w, http.StatusBadRequest, "capability is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, id, req.Capability, req.Params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (a *apiServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.auditLog())
}
