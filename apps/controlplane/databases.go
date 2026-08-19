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
// success, persists a database record — the same dispatch-then-persist-
// on-success pattern handleCreateSite and handleCreateBackup use, for the
// same reason: a raw task result alone doesn't establish that a durable
// database now exists.
//
// The owner password is never accepted from the client (that would let a
// browser or a compromised session pick a weak or reused password); it is
// generated here with a CSPRNG, exactly like a bootstrap token, and
// returned to the caller exactly once in the response body. It is never
// persisted anywhere in the control plane.
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
	if !capabilities.ValidIdentifier(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must be lowercase, start with a letter, and contain only letters, digits, and underscores (max 31 chars)")
		return
	}
	if !capabilities.ValidIdentifier(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must be lowercase, start with a letter, and contain only letters, digits, and underscores (max 31 chars)")
		return
	}

	password, err := generateDBPassword()
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

	dbRec, err := a.store.createDatabase(serverID, req.Name, req.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", req.Name, req.OwnerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       dbRec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its control-plane record. It
// requires the caller to address the database by its own id (looked up
// scoped to serverID via getDatabase) rather than accepting a bare name,
// so a request against one server can never be redirected at a
// same-named database belonging to another server.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	dbID := r.PathValue("dbId")

	dbRec, ok := a.store.getDatabase(serverID, dbID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBDelete, map[string]any{
		"name": dbRec.Name, "owner_user": dbRec.OwnerUser,
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
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", dbRec.Name, dbRec.OwnerUser))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// generateDBPassword produces a 32-character hex-encoded (128-bit)
// CSPRNG password, well above db.create's 16-character minimum.
func generateDBPassword() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
