package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateDatabase generates a strong owner password server-side (never
// caller-supplied, so a browser client can't weaken it), dispatches
// db.create, and — only on success — persists a database record. This is
// the same dispatch-then-persist-on-success pattern handleCreateSite and
// handleCreateBackup use, for the same reason: a raw task result alone
// doesn't establish that a durable database record now exists.
//
// The owner password is returned exactly once, in this response, and is
// never written to the databases table or the audit log — see db.go's
// schema comment and SECURITY.md. If the caller loses it, the only
// recovery is a password reset via db.create's idempotent
// CREATE USER IF NOT EXISTS/GRANT path re-run with a new password — not
// implemented as a dedicated capability yet (see docs/SERVERAVATAR_PARITY.md
// DB-001 "Known differences").
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !capabilities.IdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("database name must match %s (lowercase letters, digits, underscore, starting with a letter, max 31 chars)", capabilities.IdentifierRe.String()))
		return
	}

	password, err := generateDBPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreate, map[string]any{
		"name": req.Name, "owner_user": req.Name, "owner_password": password,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.create failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Name  string `json:"name"`
		Owner string `json:"owner_user"`
		Host  string `json:"host"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, result.Name, result.Owner, result.Host)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", result.Name, result.Owner))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its record — mirroring
// handleRestoreBackup's requirement that the caller can only ever act on a
// database this control plane actually knows about (identifiers come from
// the stored record, never free-form client input).
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	dbID := r.PathValue("dbId")

	rec, ok := a.store.getDatabase(serverID, dbID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBDelete, map[string]any{
		"name": rec.Name, "owner_user": rec.OwnerUser,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.delete failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.deleteDatabase(serverID, dbID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// generateDBPassword returns a 48-hex-char (192-bit) random password —
// comfortably above db.create's 16-character minimum and unguessable,
// matching createSession's rand.Read + hex.EncodeToString pattern.
func generateDBPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
