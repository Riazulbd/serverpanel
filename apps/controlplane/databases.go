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

// dbIdentifierRe mirrors packages/capabilities' own identifierRe. It is
// re-declared here (rather than imported, since capabilities.identifierRe
// is unexported by design — no other package should build SQL statements
// against it) purely so bad input gets rejected with a clear 400 before a
// task is ever dispatched to the agent. The agent re-validates independently
// and is the actual security boundary, matching the defense-in-depth
// pattern stack.install already uses (see SYSTEM.md's capability model).
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// generateDBPassword returns a random 32-character hex password for a new
// or rotated database owner user. It is returned to the caller exactly
// once, in the HTTP response, and is never persisted anywhere — the same
// "only the hash/fact of issuance is durable, never the secret itself"
// pattern store.go's bootstrap tokens use.
func generateDBPassword() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// handleCreateDatabase dispatches db.create and, only on success, persists
// the resulting database record — the same dispatch-then-persist-on-success
// pattern handleCreateSite/handleCreateBackup use, for the same reason: a
// raw task result alone doesn't establish that a durable database and its
// scoped owner user now exist.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name   string `json:"name"`
		SiteID string `json:"site_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}
	if req.SiteID != "" {
		if _, ok := a.store.getSite(serverID, req.SiteID); !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
	}

	password, err := generateDBPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}
	// The owner user shares the database's name: MySQL/MariaDB usernames and
	// database names are separate namespaces, so this can't collide with an
	// unrelated database, and it keeps "which user owns which database"
	// obvious without a separate lookup.
	ownerUser := req.Name

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

	var result struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createDatabaseRecord(serverID, req.SiteID, result.Name, result.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s site_id=%s", result.Name, result.OwnerUser, req.SiteID))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database": rec,
		// Shown once. There is no "reveal password" endpoint by design — see
		// handleResetDatabasePassword for the recovery path if this is lost.
		"password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its local record — a failed
// agent-side drop must never leave the control plane believing the
// database is gone while it still exists (and is still consuming disk/
// holding grants) on the actual server.
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

	if err := a.store.deleteDatabaseRecord(serverID, dbID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s", rec.Name))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleResetDatabasePassword rotates a database owner user's password.
// This is the only way to recover access if the password from db.create
// (returned exactly once) was lost — there is deliberately no endpoint that
// reveals a previously issued password, since the control plane never
// stores it.
func (a *apiServer) handleResetDatabasePassword(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	dbID := r.PathValue("dbId")

	rec, ok := a.store.getDatabase(serverID, dbID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	password, err := generateDBPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBSetPassword, map[string]any{
		"owner_user": rec.OwnerUser, "new_password": password,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.set_password failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "database.password_reset", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))
	writeJSON(w, http.StatusOK, map[string]string{"password": password})
}
