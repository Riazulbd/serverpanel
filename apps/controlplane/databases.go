package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// passwordAlphabet deliberately excludes characters that commonly cause
// friction when a generated password is copy-pasted into a shell, .env
// file, or connection-string URL (quotes, backslash, whitespace) while
// still giving each character a solid ~5.95 bits of entropy.
const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%^&*_+-="

// generateDatabasePassword returns a cryptographically random password long
// enough to satisfy handleDBCreate's 16-character minimum with margin.
// Passwords are never persisted by the control plane — see
// store.createDatabaseRecord's doc comment — so this is the only place the
// plaintext ever exists outside the agent's CREATE USER statement and the
// one API response the caller receives it in.
func generateDatabasePassword() (string, error) {
	const length = 24
	alphabetLen := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, length)
	for i := range out {
		n, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", err
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
}

// handleCreateDatabase dispatches db.create for a named database and,
// only on success, persists the resulting database record — the same
// dispatch-then-persist-on-success pattern handleCreateSite and
// handleCreateBackup use. The owner user shares the database's name (one
// database, one least-privilege owner, matching the agent-side capability's
// existing model — see packages/capabilities/db.go); the owner's password
// is generated here, never accepted from the client, and returned exactly
// once in this response.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !capabilities.ValidIdentifier(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must be lowercase letters, digits, and underscores, starting with a letter, up to 31 characters")
		return
	}

	password, err := generateDatabasePassword()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "could not generate a database password: "+err.Error())
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
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

	var result struct {
		Name      string `json:"name"`
		OwnerUser string `json:"owner_user"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createDatabaseRecord(serverID, result.Name, result.OwnerUser)
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

// handleDeleteDatabase dispatches db.delete and, only on success, removes
// the persisted record — the same order every other destructive capability
// in this codebase follows (see handleRestoreBackup's doc comment):
// server-side state changes only after the agent confirms the real
// operation actually happened, never optimistically first.
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
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
