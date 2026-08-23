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
// success, persists a database record — the same dispatch-then-persist-on-
// success pattern handleCreateSite/handleCreateBackup use, and for the same
// reason: a raw task result alone doesn't establish that a durable,
// listable database now exists.
//
// The owner password is never accepted from the caller and never
// persisted: it is generated here, sent once to the agent so it can be set
// as the MySQL user's password, and returned to the caller exactly once in
// the HTTP response body. This mirrors the WordPress-admin-password gap
// called out in SERVERAVATAR_PARITY.md APP-002 in the other direction — we
// deliberately don't let a caller pick (and therefore be tempted to reuse)
// a database credential, and we deliberately don't create a second place
// on disk where that credential could later leak from.
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
	if req.OwnerUser == "" {
		req.OwnerUser = req.Name
	}
	if !capabilities.IdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("name must match %s", capabilities.IdentifierRe.String()))
		return
	}
	if !capabilities.IdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("owner_user must match %s", capabilities.IdentifierRe.String()))
		return
	}
	if req.SiteID != "" {
		if _, ok := a.store.getSite(serverID, req.SiteID); !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
	}

	password, err := generateDatabasePassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate a database password")
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

	rec, err := a.store.createDatabase(serverID, req.SiteID, req.Name, req.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s site_id=%s", req.Name, req.OwnerUser, req.SiteID))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete and, only on success, removes
// the control-plane record — requiring the caller to echo back the
// database's own id in the URL, the same not-a-free-form-name-shortcut
// pattern handleRestoreBackup uses, so a caller can only ever delete a
// database this control plane actually knows about (and therefore knows
// the true owner_user for, rather than trusting a client-supplied one).
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	rec, ok := a.store.getDatabase(serverID, databaseID)
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

	if err := a.store.deleteDatabaseRecord(serverID, databaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", databaseID, rec.Name))
	w.WriteHeader(http.StatusNoContent)
}

// generateDatabasePassword returns a random 32-character hex string (128
// bits of entropy from crypto/rand) — well above db.create's own 16-
// character minimum-length check, and printable-ASCII-only so it can never
// contain a character that would need special escaping when the agent
// passes it to MariaDB as a bound parameter.
func generateDatabasePassword() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
