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

// dbIdentifierRe mirrors packages/capabilities.identifierRe. It is
// re-declared here (rather than imported — that identifier is unexported on
// the agent side, deliberately, since the agent must never trust a
// caller-supplied identifier it hasn't validated itself) so the control
// plane can reject an obviously-invalid name before ever dispatching to an
// agent, giving the browser a fast, specific error instead of a round trip.
// The agent's own check in handleDBCreate/handleDBDelete remains the real
// security boundary; this is defense in depth, not a replacement for it.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// databaseView is what a database record looks like over the API: every
// field of databaseRecord except OwnerPasswordCipher, which never leaves
// the control plane except through the explicit, audited reveal endpoint
// (handleRevealDatabasePassword) or the one-time value returned at creation.
type databaseView struct {
	ID        string
	ServerID  string
	SiteID    string
	Engine    string
	Name      string
	OwnerUser string
	Status    string
	CreatedAt time.Time
}

func toDatabaseView(rec *databaseRecord) databaseView {
	return databaseView{
		ID: rec.ID, ServerID: rec.ServerID, SiteID: rec.SiteID, Engine: rec.Engine,
		Name: rec.Name, OwnerUser: rec.OwnerUser, Status: rec.Status, CreatedAt: rec.CreatedAt,
	}
}

// handleCreateDatabase dispatches db.create for one site and, only on
// success, persists the resulting database record with its owner password
// encrypted at rest — the same dispatch-then-persist-on-success pattern
// handleCreateBackup uses. The owner password is always generated here
// (32 random bytes, hex-encoded), never accepted from the client: a
// database credential strong enough to matter shouldn't depend on a human
// picking one.
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
	if req.OwnerUser == "" {
		req.OwnerUser = req.Name
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}
	if !dbIdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+dbIdentifierRe.String())
		return
	}

	passwordBytes := make([]byte, 32)
	if _, err := rand.Read(passwordBytes); err != nil {
		writeErr(w, http.StatusInternalServerError, "failed to generate a credential")
		return
	}
	password := hex.EncodeToString(passwordBytes)

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

	cipher, err := encryptSecret(a.secretKey, password)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its credential could not be secured: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, siteID, "mariadb", req.Name, req.OwnerUser, cipher)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("site_id=%s name=%s owner_user=%s", siteID, req.Name, req.OwnerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       toDatabaseView(rec),
		"owner_password": password, // returned once, at creation time only; afterward only via the audited reveal endpoint
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	recs := a.store.listDatabases(serverID, siteID)
	views := make([]databaseView, 0, len(recs))
	for _, rec := range recs {
		views = append(views, toDatabaseView(rec))
	}
	writeJSON(w, http.StatusOK, views)
}

// handleRevealDatabasePassword decrypts and returns a previously generated
// owner password on demand. This is a POST (not a GET the way a passive
// "view" might otherwise be) and is audit-logged every time it's called,
// same as WordPress auto-login (see product-plan.md WP-003) treats access
// to a live credential as an action worth recording, not a free read.
func (a *apiServer) handleRevealDatabasePassword(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	databaseID := r.PathValue("databaseId")

	rec, ok := a.store.getDatabase(serverID, databaseID)
	if !ok {
		writeErr(w, http.StatusNotFound, "database not found")
		return
	}
	password, err := decryptSecret(a.secretKey, rec.OwnerPasswordCipher)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not decrypt stored credential: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.password_revealed", fmt.Sprintf("database_id=%s name=%s", databaseID, rec.Name))
	writeJSON(w, http.StatusOK, map[string]string{"owner_password": password})
}

// handleDeleteDatabase dispatches db.delete (which drops the real MariaDB
// database and user) and, only on success, removes the control plane's
// record — mirroring the dispatch-first-persist-after-success ordering used
// throughout (see handleCreateBackup, handleCreateDatabase): the record
// must never claim a database is gone when the drop itself failed.
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

	if err := a.store.deleteDatabase(serverID, databaseID); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was dropped on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("database_id=%s name=%s", databaseID, rec.Name))
	w.WriteHeader(http.StatusNoContent)
}
