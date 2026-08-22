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

// databaseIdentifierRe mirrors packages/capabilities/db.go's identifierRe
// exactly. It is re-validated here, before dispatch, so a malformed name is
// rejected with a 400 rather than surfacing as an opaque agent-side
// failure — the same defense-in-depth pattern handleCreateBackup's scope
// validation uses.
var databaseIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// handleCreateDatabase dispatches db.create and, only on success, persists a
// database record — the same dispatch-then-persist-on-success pattern
// handleCreateSite/handleCreateBackup use. The owner's password is generated
// here (never caller-supplied, never agent-generated-and-forgotten) and
// returned exactly once in the response body; it is never stored, matching
// createServer's single-disclosure bootstrap-token pattern. There is
// currently no way to retrieve it again later — only to reset it (a future
// db.set_password capability), which is the deliberate trade-off documented
// in docs/SERVERAVATAR_PARITY.md DB-005 rather than storing a reversibly
// encrypted secret before this project has a real key-management story.
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
	if !databaseIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+databaseIdentifierRe.String())
		return
	}
	if req.OwnerUser == "" {
		req.OwnerUser = req.Name
	}
	if !databaseIdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+databaseIdentifierRe.String())
		return
	}

	password, err := randomPassword(24)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a password")
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

	rec, err := a.store.createDatabase(serverID, result.Name, result.OwnerUser)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s", result.Name, result.OwnerUser))

	writeJSON(w, http.StatusCreated, map[string]any{
		"database":       rec,
		"owner_password": password,
	})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database, and only removes the control-plane record once the agent
// confirms the database (and its owner user) are actually gone — the same
// "never claim a state that isn't real" rule as every other destructive
// capability in this codebase.
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
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but could not be un-recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s", rec.Name))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// randomPassword returns a hex-encoded random password of at least
// nBytes*2 characters — well above db.go's 16-character minimum — generated
// with a CSPRNG, never a predictable or caller-suppliable value.
func randomPassword(nBytes int) (string, error) {
	buf := make([]byte, nBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
