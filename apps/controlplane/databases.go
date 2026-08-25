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

// dbIdentifierRe mirrors packages/capabilities.identifierRe (unexported
// there). Validating here too means a malformed name is rejected with a
// clean 400 before a task is ever dispatched to the agent, instead of
// surfacing as an opaque agent-side failure — the same validate-before-
// dispatch shape handleCreateBackup uses for scope/db_name.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create for one server and, only on
// success, persists a database record — the same dispatch-then-persist-on-
// success pattern used for sites and backups. The owner password is
// generated here, sent to the agent for the CREATE USER statement, returned
// once in this response, and never written to the store: nothing durable in
// the control plane could leak it later.
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
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}
	ownerUser := req.OwnerUser
	if ownerUser == "" {
		ownerUser = req.Name
	}
	if !dbIdentifierRe.MatchString(ownerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+dbIdentifierRe.String())
		return
	}

	rawPassword := make([]byte, 24)
	if _, err := rand.Read(rawPassword); err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate owner password")
		return
	}
	password := hex.EncodeToString(rawPassword) // 48 chars, well over db.create's 16-char minimum

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
		writeErr(w, http.StatusInternalServerError, "database created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("db_id=%s name=%s owner_user=%s", rec.ID, req.Name, ownerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"ID": rec.ID, "ServerID": rec.ServerID, "Name": rec.Name, "OwnerUser": rec.OwnerUser,
		"Status": rec.Status, "CreatedAt": rec.CreatedAt,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its record — a dropped database
// can't be un-dropped from here (unlike a site or server, there's no
// "revoke" state that still lets the record be looked up), so this call
// requires the caller to name the exact database ID, matching
// handleRestoreBackup's no-ambiguity requirement.
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
		writeErr(w, http.StatusInternalServerError, "database deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("db_id=%s name=%s", dbID, rec.Name))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
