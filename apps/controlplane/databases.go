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

// identifierRe mirrors packages/capabilities.identifierRe (that package
// isn't importable here without exporting it, and duplicating one strict
// regex is simpler and safer than exporting agent-side validation surface
// just for this). Both sides validate independently — defense in depth,
// same pattern as SRV-002's dual OS/resource preflight checks.
var identifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// generateDBPassword returns a random 32-hex-character (16-byte) secret.
// It is returned to the caller exactly once in the API response and never
// persisted anywhere in the control plane — the same "we never store a
// reusable plaintext credential" property ACC-001/WP-AUTOLOGIN's design
// notes call for, applied here to database credentials too.
func generateDBPassword() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}

// handleCreateDatabase dispatches db.create and, only on success, persists
// a database record — the dispatch-then-persist-on-success pattern
// handleCreateSite/handleCreateBackup use, for the same reason: a raw task
// result alone doesn't establish that a durable database now exists. The
// owner password is generated server-side (never accepted from the
// client, so a caller can't set a weak one) and returned exactly once.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
		SiteID    string `json:"site_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.OwnerUser == "" {
		writeErr(w, http.StatusBadRequest, "name and owner_user are required")
		return
	}
	if !identifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+identifierRe.String())
		return
	}
	if !identifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+identifierRe.String())
		return
	}
	if req.SiteID != "" {
		if _, ok := a.store.getSite(serverID, req.SiteID); !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
	}
	if a.store.databaseNameInUse(serverID, req.Name) {
		writeErr(w, http.StatusConflict, "a database named "+req.Name+" already exists on this server")
		return
	}

	password, err := generateDBPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a credential")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreate, map[string]any{
		"name": req.Name, "owner_user": req.OwnerUser, "owner_password": password,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.create failed on the agent: "+ev.Message)
		return
	}

	rec, err := a.store.createDatabase(serverID, req.SiteID, req.Name, req.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", req.Name, req.OwnerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete (which drops the database and
// its owner user) and, only on success, removes the database record and
// its scoped-user records. This is destructive and irreversible on the
// agent side — the client is responsible for the confirmation prompt
// (see web/index.html), matching restoreBackup's pattern.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("dbId")

	rec, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
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

	if err := a.store.deleteDatabase(serverID, databaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", "name="+rec.Name)
	w.WriteHeader(http.StatusNoContent)
}

// handleCreateDatabaseUser adds an additional scoped user to an existing
// database (e.g. a read/write credential for a second app or integration
// sharing the same database) without touching the owner user's grants.
func (a *apiServer) handleCreateDatabaseUser(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("dbId")

	db, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	var req struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" {
		writeErr(w, http.StatusBadRequest, "username is required")
		return
	}
	if !identifierRe.MatchString(req.Username) {
		writeErr(w, http.StatusBadRequest, "username must match "+identifierRe.String())
		return
	}

	password, err := generateDBPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a credential")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreateUser, map[string]any{
		"db_name": db.Name, "username": req.Username, "password": password,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.create_user failed on the agent: "+ev.Message)
		return
	}

	rec, err := a.store.createDatabaseUser(serverID, databaseID, req.Username)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "user was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.user_created", fmt.Sprintf("database_id=%s username=%s", databaseID, req.Username))

	writeJSON(w, http.StatusCreated, map[string]any{
		"user":     rec,
		"password": password,
	})
}

func (a *apiServer) handleListDatabaseUsers(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	databaseID := r.PathValue("dbId")
	if _, ok := a.store.getDatabase(serverID, databaseID); !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listDatabaseUsers(serverID, databaseID))
}

func (a *apiServer) handleDeleteDatabaseUser(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("dbId")
	userID := r.PathValue("userId")

	user, ok := a.store.getDatabaseUser(serverID, databaseID, userID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database user not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBDeleteUser, map[string]any{
		"username": user.Username,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.delete_user failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.deleteDatabaseUser(serverID, databaseID, userID); err != nil {
		writeErr(w, http.StatusInternalServerError, "user was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.user_deleted", fmt.Sprintf("database_id=%s username=%s", databaseID, user.Username))
	w.WriteHeader(http.StatusNoContent)
}
