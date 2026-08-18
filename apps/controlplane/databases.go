package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// dbNameRe mirrors packages/capabilities.identifierRe (the agent's own
// allow-list for MySQL/MariaDB identifiers). Validating here too means a
// caller gets a clear 400 instead of a confusing 502/dispatch failure for
// something as simple as an uppercase database name.
var dbNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create with a control-plane-generated
// owner username/password — never a caller-supplied password — and, only on
// success, persists a durable record with that password encrypted at rest
// (secretBox, secrets.go). This is the same dispatch-then-persist-on-success
// pattern handleCreateBackup uses, for the same reason: a bare task result
// doesn't establish that a durable, reusable database now exists.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name   string `json:"name"`
		SiteID string `json:"site_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !dbNameRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbNameRe.String())
		return
	}
	if req.SiteID != "" {
		if _, ok := a.store.getSite(serverID, req.SiteID); !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
	}

	// The database name doubles as its owner username: simplest possible
	// mapping, and it keeps a glance at "wp_example" self-explanatory rather
	// than needing a second generated identifier to track.
	ownerUser := req.Name
	password, err := randomPassword(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
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

	encPassword, err := a.secrets.encrypt(password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database created but its credential could not be sealed for storage: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, req.SiteID, req.Name, ownerUser, encPassword)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database created but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s site_id=%s", req.Name, ownerUser, req.SiteID))

	// The plaintext password is returned exactly once, here, at creation —
	// matching createServer's one-time bootstrap-token display. Every
	// later read (handleListDatabases) omits it; a caller who needs it
	// again must go through handleRevealDatabasePassword, which is
	// separately audit-logged.
	writeJSON(w, http.StatusCreated, map[string]any{
		"ID": rec.ID, "ServerID": rec.ServerID, "SiteID": rec.SiteID, "Name": rec.Name,
		"OwnerUser": rec.OwnerUser, "Password": password, "Status": rec.Status, "CreatedAt": rec.CreatedAt,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	recs := a.store.listDatabases(serverID)
	out := make([]map[string]any, 0, len(recs))
	for _, rec := range recs {
		out = append(out, map[string]any{
			"ID": rec.ID, "ServerID": rec.ServerID, "SiteID": rec.SiteID, "Name": rec.Name,
			"OwnerUser": rec.OwnerUser, "Status": rec.Status, "CreatedAt": rec.CreatedAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRevealDatabasePassword decrypts and returns a database's owner
// password on demand. This is a separate, explicitly-invoked endpoint
// (rather than folding the password into handleListDatabases) so that
// listing databases never has a side effect of decrypting every credential
// on the server, and so every reveal gets its own audit-log entry.
func (a *apiServer) handleRevealDatabasePassword(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	dbID := r.PathValue("dbId")

	rec, ok := a.store.getDatabase(serverID, dbID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}
	password, err := a.secrets.decrypt(rec.OwnerPasswordEnc)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "stored credential could not be decrypted: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.password_revealed", fmt.Sprintf("database_id=%s name=%s", dbID, rec.Name))
	writeJSON(w, http.StatusOK, map[string]string{"owner_user": rec.OwnerUser, "password": password})
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes its control-plane record — the
// same order handleRestoreBackup logs failures/successes in, so the
// database row never silently diverges from what actually exists (or
// doesn't) on the server.
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
		a.store.log(serverID, actor, "database.delete_failed", fmt.Sprintf("database_id=%s: %s", dbID, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "db.delete failed on the agent: "+ev.Message)
		return
	}

	if err := a.store.deleteDatabase(serverID, dbID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database dropped on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", dbID, rec.Name))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
