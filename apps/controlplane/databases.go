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

// dbNameRe mirrors packages/capabilities/db.go's identifierRe. Validating
// the same allow-list here lets a malformed name be rejected with a clean
// 400 before ever dispatching to the agent, rather than surfacing as an
// opaque 502/422 from the agent's own (equally strict) check.
var dbNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// generateDBPassword returns a random 48-hex-character (24-byte) password.
// It is never persisted — see handleCreateDatabase — only ever sent to the
// agent for the CREATE USER ... IDENTIFIED BY statement and returned to the
// caller exactly once in the create response, the same "shown once, stored
// nowhere" pattern the bootstrap-token install command uses (store.go
// createServer).
func generateDBPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// handleCreateDatabase dispatches db.create to the agent and, only on
// success, persists a database record — the same dispatch-then-persist
// pattern handleCreateSite/handleCreateBackup use. The owner username is
// always the same as the database name (one least-privilege owner per
// database, matching db.create's grant model of "scoped to exactly one
// database, never GRANT ALL at server scope"); the owner password is
// generated here, never caller-supplied and never stored — it is returned
// to the caller exactly once so it can be handed to whatever application
// will use this database.
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
	if !dbNameRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbNameRe.String()+" (lowercase letters, digits, underscore; must start with a letter)")
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
		writeErr(w, http.StatusInternalServerError, "could not generate a database password: "+err.Error())
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
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, req.SiteID, result.Name, result.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", result.Name, result.OwnerUser))

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
// database and, only on success, removes its record — the same
// confirm-before-destroy shape backups.go's handleRestoreBackup uses. The
// caller supplies only the database's own id in the URL (never a free-form
// database name), so this can only ever act on a database this control
// plane actually created and recorded for this server.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	rec, ok := a.store.getDatabase(serverID, databaseID)
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

	if err := a.store.deleteDatabase(serverID, databaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", databaseID, rec.Name))

	w.WriteHeader(http.StatusNoContent)
}
