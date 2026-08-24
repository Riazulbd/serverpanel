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

// dbIdentifierRe mirrors packages/capabilities.identifierRe (the agent-side
// allow-list db.create/db.delete enforce) so an obviously invalid name is
// rejected here, before ever reaching the agent, with a clear error instead
// of an opaque agent-side failure.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create and, only on success, persists
// a database record — the same dispatch-then-persist-on-success pattern
// handleCreateSite and handleCreateBackup use, for the same reason: a raw
// task result alone doesn't establish that a durable database now exists.
//
// The owner password is always generated here, server-side, rather than
// accepted from the client: it is returned exactly once in this response
// and never stored (not in the databases table, not in the audit log
// detail), matching the bootstrap-token model in store.go.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
		SiteID    string `json:"site_id"`
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
	if req.SiteID != "" {
		if _, ok := a.store.getSite(serverID, req.SiteID); !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
	}

	password, err := generateDBPassword()
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

	rec, err := a.store.createDatabase(serverID, req.SiteID, req.Name, ownerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", req.Name, ownerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password, // returned exactly once; never persisted
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

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its control-plane record — the
// same destructive-action pattern handleRestoreBackup uses (server-side
// lookup of the record's own name/owner, never caller-supplied free-form
// values, so a caller can only ever delete a database that was actually
// created and recorded through this control plane).
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
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// generateDBPassword returns a 24-byte, base64url-encoded random password
// (32 characters, well above db.create's 16-character minimum) — the same
// crypto/rand-backed approach store.createServer uses for bootstrap tokens.
func generateDBPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
