package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// dbIdentifierRe mirrors packages/capabilities/db.go's identifierRe — kept
// as a separate copy (not an import) because the control plane and the
// agent are independent trust boundaries; validating here too means a
// malformed name is rejected before a task is ever dispatched, not just
// when it reaches the agent.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create for one site and, only on
// success, persists the resulting database record — the same
// dispatch-then-persist-on-success pattern handleCreateSite/
// handleCreateBackup use. The owner password is generated here, server
// side, never accepted from the caller and never stored anywhere after
// this response: it is returned exactly once so the caller can save it,
// the same one-time-reveal model bootstrap tokens use.
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

	var result struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	db, err := a.store.createDatabase(serverID, siteID, result.Name, result.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("site_id=%s name=%s owner_user=%s", siteID, result.Name, result.OwnerUser))

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
// database and, only once the agent confirms it, removes the control
// plane's own record — never the other order, so a failed drop never
// leaves the dashboard claiming a database is gone when it isn't.
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

	a.store.deleteDatabase(serverID, databaseID)
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", databaseID, db.Name))
	w.WriteHeader(http.StatusNoContent)
}

// generateDBPassword returns a 24-byte cryptographically random password,
// base64url-encoded (32 chars, well over handleDBCreate/handleDBCreate's
// agent-side 16-character minimum) — the same crypto/rand approach
// auth.go's session tokens and totp.go's TOTP secrets use, applied here
// because a database owner's credential deserves the same treatment.
func generateDBPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
