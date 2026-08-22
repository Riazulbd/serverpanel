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

// dbIdentifierRe mirrors packages/capabilities.identifierRe (unexported,
// agent-only) exactly. Re-validating the same untrusted input here, before
// it's ever sent to the agent, is defense in depth — see SECURITY.md — not
// a substitute for the agent's own check, which still runs regardless.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create to the agent and, only on
// success, persists a database record — the same dispatch-then-persist
// pattern handleCreateSite/handleCreateBackup use. The owner password is
// always generated here, never accepted from the client: db.create's own
// 16-character minimum exists precisely so a weak, attacker-chosen, or
// reused password can never end up granted database access.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.OwnerUser == "" {
		writeErr(w, http.StatusBadRequest, "name and owner_user are required")
		return
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}
	if !dbIdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+dbIdentifierRe.String())
		return
	}

	passwordRaw := make([]byte, 24)
	if _, err := rand.Read(passwordRaw); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}
	password := hex.EncodeToString(passwordRaw) // 48 chars, well above db.create's 16-char minimum

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

	enc, err := a.secrets.Encrypt(password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its password could not be sealed for storage: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, req.Name, req.OwnerUser, enc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", req.Name, req.OwnerUser))

	// The plaintext password is returned exactly once, here, at creation
	// time — matching the bootstrap-token pattern (store.createServer).
	// After this response it only ever exists encrypted at rest; retrieving
	// it again goes through handleRevealDatabasePassword, which is audited.
	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.listDatabases(r.PathValue("id")))
}

// handleRevealDatabasePassword decrypts and returns a previously created
// database's owner password. Every call is audit-logged (action
// "database.password_revealed") since, unlike most reads, this one exposes
// a live credential.
func (a *apiServer) handleRevealDatabasePassword(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	dbID := r.PathValue("dbId")

	rec, ok := a.store.getDatabase(serverID, dbID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}
	password, err := a.secrets.Decrypt(rec.OwnerPasswordEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stored credential could not be decrypted: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.password_revealed", fmt.Sprintf("database_id=%s", dbID))
	writeJSON(w, http.StatusOK, map[string]string{"owner_password": password})
}

// handleDeleteDatabase dispatches db.delete and, only on success, removes
// the record — never the other way around, so a failed agent-side delete
// never leaves a dangling control-plane record pointing at a database that
// no longer exists (or worse, silently drops the record for one that
// actually still does).
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
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", dbID, rec.Name))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
