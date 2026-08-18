package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// dbIdentifierRe mirrors packages/capabilities/db.go's identifierRe. The
// control plane re-checks it before ever dispatching db.create/db.delete —
// defense in depth, not a replacement for the agent-side check, matching
// the pattern stack.install's OS check and the file manager's path
// confinement use elsewhere in this codebase (never trust only one layer).
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create for a MySQL/MariaDB database and,
// only on success, persists the resulting database record — the same
// dispatch-then-persist-on-success pattern handleCreateSite/handleCreateBackup
// use, for the same reason: a raw task result alone doesn't establish that a
// durable database now exists.
//
// The owner user's password is generated here (cryptographically random,
// never caller-supplied, never agent-generated either — this is the one
// place it exists in plaintext), handed to the agent so it can set it, and
// returned to the caller exactly once in the HTTP response. It is never
// written to the database, logs, or the audit trail — see store.go
// createDatabase's doc comment.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	ownerUser := req.OwnerUser
	if ownerUser == "" {
		ownerUser = req.Name
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "database name must match "+dbIdentifierRe.String())
		return
	}
	if !dbIdentifierRe.MatchString(ownerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+dbIdentifierRe.String())
		return
	}

	password, err := randomPassword(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreate, map[string]any{
		"name": req.Name, "owner_user": ownerUser, "owner_password": password,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.create failed on the agent: "+ev.Message)
		return
	}

	rec, err := a.store.createDatabase(serverID, req.Name, ownerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", req.Name, ownerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete and, only on success, removes
// the control-plane record — the same ordering handleRestoreBackup uses for
// its own destructive action, so a failed drop on the agent never leaves a
// database silently missing from the dashboard while it still exists (or
// vice versa).
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	dbID := r.PathValue("dbId")

	rec, ok := a.store.getDatabase(serverID, dbID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
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
		writeErr(w, http.StatusInternalServerError, "database was dropped on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func randomPassword(nBytes int) (string, error) {
	raw := make([]byte, nBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
