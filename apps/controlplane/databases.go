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

// dbIdentifierRe mirrors packages/capabilities.identifierRe. It is
// re-validated here, before dispatch, for the same reason
// handleCreateBackup re-validates scope: the agent-side check is the real
// security boundary, but rejecting an obviously-invalid name locally saves
// a round trip and keeps error messages consistent with the rest of the
// API.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create for one site and, only on
// success, persists the resulting database record — the same
// dispatch-then-persist-on-success pattern handleCreateSite/
// handleCreateBackup use, for the same reason: a raw task result alone
// doesn't establish that a durable database now exists.
//
// The owner user and its password are generated here, server-side, rather
// than accepted from the client: this is the only place a plaintext
// database password is ever visible, and it is returned once in the HTTP
// response and never stored anywhere (matching how bootstrap tokens are
// handled — see store.createServer).
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}

	owner, err := ownerUserFor(req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	password, err := randomPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreate, map[string]any{
		"name": req.Name, "owner_user": owner, "owner_password": password,
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
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, siteID, result.Name, result.Owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("site_id=%s name=%s owner_user=%s", siteID, result.Name, result.Owner))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID, siteID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, marks the record deleted. As with
// handleRestoreBackup, the name/owner_user dispatched to the agent are
// read server-side from the stored row, never accepted as free-form client
// input — a caller can only ever delete a database that was actually
// created and recorded through this API.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	rec, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}
	if rec.Status == "deleted" {
		writeErr(w, http.StatusConflict, "database was already deleted")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
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

	if err := a.store.markDatabaseDeleted(serverID, databaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", databaseID, rec.Name))

	w.WriteHeader(http.StatusNoContent)
}

// ownerUserFor derives a deterministic, identifierRe-safe owner username
// from a database name plus a short random suffix (so two databases with
// names that truncate to the same prefix never collide on their owner
// user). Bounded to identifierRe's 31-character limit.
func ownerUserFor(dbName string) (string, error) {
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return "", err
	}
	suffixHex := hex.EncodeToString(suffix) // 6 hex chars
	maxNameLen := 31 - len("_u") - len(suffixHex)
	name := dbName
	if len(name) > maxNameLen {
		name = name[:maxNameLen]
	}
	return name + "_u" + suffixHex, nil
}

// randomPassword generates a cryptographically random password long enough
// to satisfy handleDBCreate's 16-character minimum with headroom. It is
// returned to the caller exactly once (see handleCreateDatabase) and never
// persisted by the control plane.
func randomPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil // 48 chars
}
