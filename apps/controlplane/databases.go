package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// dbIdentifierRe mirrors packages/capabilities/db.go's identifierRe exactly.
// It's kept as its own copy (rather than an import) so the control plane
// never needs to depend on the agent's capability package for anything
// beyond dispatching tasks by name — but validating the same shape here
// means an invalid name/owner_user is rejected with a fast 400 instead of a
// round trip to a possibly-offline or slow agent.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create to the agent and, only on
// success, persists a database record — the same dispatch-then-persist
// pattern handleCreateSite/handleCreateBackup use. The owner password is
// generated here (never accepted from the client, so a caller can't force
// a weak or reused password), returned once in the creation response, and
// stored only in encrypted form thereafter (see secrets.go).
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	if _, ok := a.store.get(serverID); !ok {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	}

	var req struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.OwnerUser == "" {
		req.OwnerUser = req.Name
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}
	if !dbIdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+dbIdentifierRe.String())
		return
	}

	password, err := randomPassword(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
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

	passwordEnc, err := encryptSecret(a.secretKey, password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its credentials could not be stored securely: "+err.Error())
		return
	}

	db, err := a.store.createDatabase(serverID, req.Name, req.OwnerUser, passwordEnc)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, http.StatusConflict, "a database named "+req.Name+" is already recorded on this server")
			return
		}
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("database_id=%s name=%s owner_user=%s", db.ID, req.Name, req.OwnerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       db,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	if _, ok := a.store.get(serverID); !ok {
		writeErr(w, http.StatusNotFound, "server not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleGetDatabaseCredentials decrypts and returns a previously created
// database's owner password on demand — the only place the plaintext
// password is ever reconstituted after creation. Every call is audit
// logged, since replaying a database's credentials is itself a sensitive
// action worth a durable record.
func (a *apiServer) handleGetDatabaseCredentials(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	db, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	password, err := decryptSecret(a.secretKey, db.OwnerPasswordEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not decrypt stored credentials: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.credentials_viewed", "database_id="+databaseID+" name="+db.Name)

	writeJSON(w, http.StatusOK, map[string]any{
		"name": db.Name, "owner_user": db.OwnerUser, "owner_password": password,
	})
}

// handleDeleteDatabase dispatches db.delete to the agent and, only on
// success, removes the control-plane record — never the reverse, so a
// failed agent-side drop never silently loses the panel's only record that
// the database (and its credentials) still exist.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	db, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBDelete, map[string]any{
		"name": db.Name, "owner_user": db.OwnerUser,
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
	a.store.log(serverID, actor, "database.deleted", "database_id="+databaseID+" name="+db.Name)
	w.WriteHeader(http.StatusNoContent)
}

func randomPassword(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
