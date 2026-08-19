package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// databaseIdentifierRe mirrors packages/capabilities.identifierRe exactly
// (MySQL/MariaDB identifiers can't use a placeholder, so both the agent and
// the control plane independently allow-list the charset before it ever
// reaches a CREATE DATABASE/USER statement — defense in depth, not trust in
// one layer's validation alone).
var databaseIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create for one site and, only on
// success, persists a database record — the same dispatch-then-persist-on-
// success pattern handleCreateSite/handleCreateBackup use.
//
// The owner password is generated here (never accepted from the client,
// never reused across databases), handed to the agent to actually set, and
// returned to the caller exactly once in the response body. It is not
// persisted anywhere — see createDatabase's doc comment for why.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
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
	if !databaseIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+databaseIdentifierRe.String())
		return
	}
	ownerUser := req.OwnerUser
	if ownerUser == "" {
		ownerUser = req.Name
	}
	if !databaseIdentifierRe.MatchString(ownerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+databaseIdentifierRe.String())
		return
	}

	password, err := randomPassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
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

	db, err := a.store.createDatabase(serverID, siteID, req.Name, ownerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", "site_id="+siteID+" name="+req.Name+" owner_user="+ownerUser)

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       db,
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
// database and, only on success, removes its control-plane record — a
// destructive action, gated by the same explicit per-resource-ID addressing
// (never "delete the last one") and client-side confirmation dialog pattern
// used by backup restore.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	db, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
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
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// randomPassword returns a 48-hex-character (24-byte) cryptographically
// random password, well above handleDBCreate's 16-character minimum.
func randomPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
