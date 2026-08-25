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

// handleCreateDatabase dispatches db.create for one server and, only on
// success, persists the resulting database record — the same
// dispatch-then-persist-on-success pattern handleCreateBackup/handleCreateSite
// use, for the same reason: a raw task result alone doesn't establish that
// a durable database now exists on that server.
//
// The owner password is generated here, server-side, with the same
// crypto/rand + hex approach createServer uses for bootstrap tokens: it is
// sent to the agent to set as the MySQL user's password and returned once
// in this response, but it is never written to the databases table or
// logged. There is no "view password again" feature by design — the same
// property applies to every credential this control plane hands back
// (bootstrap tokens, backups' checksums), matching ACC-*'s "never store
// plaintext" requirement here for database owner passwords.
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
	if req.OwnerUser == "" {
		req.OwnerUser = req.Name
	}
	if !capabilities.ValidDBIdentifier(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match ^[a-z][a-z0-9_]{0,30}$")
		return
	}
	if !capabilities.ValidDBIdentifier(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match ^[a-z][a-z0-9_]{0,30}$")
		return
	}

	password, err := randomPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
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

	rec, err := a.store.createDatabaseRecord(serverID, req.Name, req.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", req.Name, req.OwnerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":             rec.ID,
		"name":           rec.Name,
		"owner_user":     rec.OwnerUser,
		"owner_password": password,
		"created_at":     rec.CreatedAt,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its control-plane record — the
// same order backup.restore uses (act on the agent first, then update the
// durable record), so the two never drift out of sync on a failure.
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

	if err := a.store.deleteDatabaseRecord(serverID, dbID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func randomPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
