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

// dbIdentifierRe mirrors packages/capabilities/db.go's identifierRe. It is
// re-declared here (rather than exported and imported) so the control plane
// validates and rejects an obviously-bad name before ever dispatching to an
// agent — defense in depth, not the only check: the agent independently
// re-validates the same pattern before it ever reaches a SQL statement.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create for one site and, only on
// success, persists the resulting database record — the same
// dispatch-then-persist-on-success pattern handleCreateBackup and
// handleCreateSite use. The owner password is generated here (server-side,
// cryptographically random), never accepted from the caller: this is what
// keeps a database's credentials from ever being a weak, reused, or
// caller-guessable value. It is returned exactly once in the response and
// is never persisted in the store — the same "shown once" treatment
// bootstrap tokens get.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String()+" (lowercase letters, digits, underscore, starting with a letter, max 31 chars)")
		return
	}

	password, err := randomPassword(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreate, map[string]any{
		"name": req.Name, "owner_user": req.Name, "owner_password": password,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "db.create failed on the agent: "+ev.Message)
		return
	}

	rec, err := a.store.createDatabaseRecord(serverID, siteID, req.Name, req.Name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("site_id=%s name=%s owner_user=%s", siteID, req.Name, req.Name))

	writeJSON(w, http.StatusCreated, struct {
		*databaseRecord
		Password string `json:"password"`
	}{rec, password})
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

// handleDeleteDatabase dispatches db.delete and, only on success, removes
// the control-plane record — mirroring handleCreateDatabase's
// dispatch-then-mutate-on-success ordering so the store is never out of
// sync with what actually exists on the agent's MariaDB instance.
func (a *apiServer) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	rec, ok := a.store.getDatabase(serverID, databaseID)
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

	if err := a.store.deleteDatabaseRecord(serverID, databaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", databaseID, rec.Name))
	w.WriteHeader(http.StatusNoContent)
}

// randomPassword returns a cryptographically random, URL-safe-ish hex
// password of the given byte length (so a 24-byte request yields a 48-
// character string) — well over db.create's 16-character minimum with
// plenty of margin, and free of characters that could complicate copy/paste
// or embedding in a connection string.
func randomPassword(nBytes int) (string, error) {
	raw := make([]byte, nBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
