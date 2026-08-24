package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// generateDatabasePassword returns a cryptographically random password for
// a new database owner user. The control plane generates this itself — it
// is never accepted from the client, so a caller can't choose a weak
// owner_password — and returns it to the caller exactly once in the
// create-database response; like a bootstrap token, only the fact that a
// password was issued is ever persisted (via the agent's own MySQL user
// record), never the plaintext value.
func generateDatabasePassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// handleCreateDatabase dispatches db.create and, only on success, persists
// a database record — the same dispatch-then-persist-on-success pattern
// handleCreateSite/handleCreateBackup use (apps/controlplane/sites.go,
// backups.go), and for the same reason: a raw task result alone doesn't
// establish that a durable database now exists on this server.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
		SiteID    string `json:"site_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || req.OwnerUser == "" {
		writeErr(w, http.StatusBadRequest, "name and owner_user are required")
		return
	}
	// Validated here too (not just agent-side in packages/capabilities) so a
	// bad name is rejected before ever reaching the agent dispatch — the
	// same defense-in-depth the site/backup endpoints already apply to
	// their own inputs.
	if !capabilities.IdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+capabilities.IdentifierRe.String())
		return
	}
	if !capabilities.IdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+capabilities.IdentifierRe.String())
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

	db, err := a.store.createDatabase(serverID, req.SiteID, req.Name, req.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s site_id=%s", req.Name, req.OwnerUser, req.SiteID))

	// owner_password is returned exactly once, here, and nowhere else —
	// there is no "show password again" endpoint, matching how the
	// bootstrap-token plaintext is handled.
	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       db,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete and, only on success, removes
// the persisted record — the create path's dispatch-then-persist
// discipline in reverse: the row is only removed once the agent confirms
// the database and its owner user are actually gone.
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
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but could not be removed from records: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", dbID, rec.Name))

	w.WriteHeader(http.StatusNoContent)
}
