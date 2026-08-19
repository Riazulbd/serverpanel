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
// Every /api/v1/* route requires an authenticated, MFA-satisfied session
// (see auth.go requireAuth); only registration, login/signup, and the MFA
// challenge endpoint are reachable without one, matching the routes listed
// in routes() below exactly.
type apiServer struct {
	store       *store
	ca          *agentCA
	gw          *gateway
	gatewayAddr string
	tokenTTL    time.Duration
	publicDir   string // static dashboard assets; see dashboard.go
}

func (a *apiServer) routes() http.Handler {
	mux := http.NewServeMux()

	// Agent-facing: no session, authenticated instead by the one-time
	// bootstrap token (see docs/security-trust-model.md §1).
	mux.HandleFunc("POST /agents/register", a.handleRegister)

	// Auth: unauthenticated by definition (this is how a session is
	// obtained), except /api/v1/auth/me which requires one.
	mux.HandleFunc("POST /api/v1/auth/signup", a.handleSignup)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", a.handleLogout)
	mux.HandleFunc("POST /api/v1/auth/mfa/challenge", a.handleMFAChallenge)
	mux.HandleFunc("GET /api/v1/auth/me", a.requireAuth(a.handleMe))
	mux.HandleFunc("POST /api/v1/auth/totp/enroll", a.requireAuth(a.handleTOTPEnroll))
	mux.HandleFunc("POST /api/v1/auth/totp/verify", a.requireAuth(a.handleTOTPVerify))

	// Everything else that manages servers/tasks/audit requires a full
	// session.
	mux.HandleFunc("POST /api/v1/servers", a.requireAuth(a.handleCreateServer))
	mux.HandleFunc("GET /api/v1/servers", a.requireAuth(a.handleListServers))
	mux.HandleFunc("GET /api/v1/servers/{id}", a.requireAuth(a.handleGetServer))
	mux.HandleFunc("POST /api/v1/servers/{id}/revoke", a.requireAuth(a.handleRevokeServer))
	mux.HandleFunc("POST /api/v1/servers/{id}/tasks", a.requireAuth(a.handleDispatchTask))
	mux.HandleFunc("GET /api/v1/servers/{id}/sites", a.requireAuth(a.handleListSites))
	mux.HandleFunc("POST /api/v1/servers/{id}/sites", a.requireAuth(a.handleCreateSite))
	mux.HandleFunc("GET /api/v1/servers/{id}/sites/{siteId}/backups", a.requireAuth(a.handleListBackups))
	mux.HandleFunc("POST /api/v1/servers/{id}/sites/{siteId}/backups", a.requireAuth(a.handleCreateBackup))
	mux.HandleFunc("POST /api/v1/servers/{id}/backups/{backupId}/restore", a.requireAuth(a.handleRestoreBackup))
	mux.HandleFunc("GET /api/v1/servers/{id}/databases", a.requireAuth(a.handleListDatabases))
	mux.HandleFunc("POST /api/v1/servers/{id}/databases", a.requireAuth(a.handleCreateDatabase))
	mux.HandleFunc("DELETE /api/v1/servers/{id}/databases/{dbId}", a.requireAuth(a.handleDeleteDatabase))
	mux.HandleFunc("POST /api/v1/servers/{id}/databases/{dbId}/reset-password", a.requireAuth(a.handleResetDatabasePassword))
	mux.HandleFunc("GET /api/v1/audit", a.requireAuth(a.handleAudit))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })

	a.mountDashboard(mux)
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
	actor := sessionFromContext(r.Context()).Email
	var req struct {
		Name  string   `json:"name"`
		Group string   `json:"group"`
		Tags  []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	id, token, err := a.store.createServer(req.Name, req.Group, req.Tags, a.tokenTTL, actor)
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
	actor := sessionFromContext(r.Context()).Email
	id := r.PathValue("id")
	if err := a.store.revokeServer(id, actor); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	a.store.revokeToken(id, actor)
	a.gw.forceDisconnect(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

func (a *apiServer) handleDispatchTask(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	id := r.PathValue("id")
	var req struct {
		Capability string         `json:"capability"`
		Params     map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Capability == "" {
		writeErr(w, http.StatusBadRequest, "capability is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, id, actor, req.Capability, req.Params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ev)
}

func (a *apiServer) handleAudit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.auditLog())
}

func (a *apiServer) handleListSites(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listSites(id))
}
