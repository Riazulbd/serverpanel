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

// identifierRe mirrors packages/capabilities.identifierRe. It is
// duplicated (not imported — that package intentionally exposes no public
// API surface beyond the capability registry) so the control plane can
// reject an obviously-invalid name before spending a round trip to the
// agent, while the agent's own copy remains the actual enforcement point.
var dbIdentifierRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,30}$`)

// generateDBPassword returns a random password that satisfies db.create's
// minimum-length requirement. It is returned to the caller exactly once,
// in the HTTP response, and is never persisted — the same
// shown-once-never-stored pattern used for a server's bootstrap install
// token (see store.go createServer).
func generateDBPassword() (string, error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil // 32 chars, well over db.create's 16-char minimum
}

// handleCreateDatabase dispatches db.create and, only on success, persists
// the resulting database record — the same dispatch-then-persist-on-success
// pattern handleCreateBackup and handleCreateSite use, and for the same
// reason: a raw task result alone doesn't establish that a durable database
// now exists.
func (a *apiServer) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Name          string `json:"name"`
		OwnerUser     string `json:"owner_user"`
		OwnerPassword string `json:"owner_password"`
		SiteID        string `json:"site_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "name is required")
		return
	}
	if !dbIdentifierRe.MatchString(req.Name) {
		writeErr(w, http.StatusBadRequest, "name must match "+dbIdentifierRe.String())
		return
	}
	if req.OwnerUser == "" {
		req.OwnerUser = req.Name
	}
	if !dbIdentifierRe.MatchString(req.OwnerUser) {
		writeErr(w, http.StatusBadRequest, "owner_user must match "+dbIdentifierRe.String())
		return
	}
	if req.SiteID != "" {
		if _, ok := a.store.getSite(serverID, req.SiteID); !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
	}

	generatedPassword := req.OwnerPassword == ""
	if generatedPassword {
		pw, err := generateDBPassword()
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not generate a database password: "+err.Error())
			return
		}
		req.OwnerPassword = pw
	} else if len(req.OwnerPassword) < 16 {
		writeErr(w, http.StatusBadRequest, "owner_password must be at least 16 characters")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapDBCreate, map[string]any{
		"name": req.Name, "owner_user": req.OwnerUser, "owner_password": req.OwnerPassword,
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
		Name  string `json:"name"`
		Owner string `json:"owner_user"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createDatabase(serverID, req.SiteID, result.Name, result.Owner)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "database was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.created", fmt.Sprintf("name=%s owner_user=%s site_id=%s", result.Name, result.Owner, req.SiteID))

	writeJSON(w, http.StatusCreated, struct {
		*databaseRecord
		OwnerPassword     string `json:"owner_password,omitempty"`
		PasswordGenerated bool   `json:"password_generated"`
	}{databaseRecord: rec, OwnerPassword: req.OwnerPassword, PasswordGenerated: generatedPassword})
}

func (a *apiServer) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listDatabases(serverID))
}

// handleDeleteDatabase dispatches db.delete for a previously recorded
// database and, only on success, removes the control-plane record — the
// database and its scoped owner user must actually be gone on the server
// before this panel stops showing it as existing.
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
		writeErr(w, http.StatusInternalServerError, "database was deleted on the agent but its record could not be removed: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "database.deleted", fmt.Sprintf("name=%s owner_user=%s", rec.Name, rec.OwnerUser))

	w.WriteHeader(http.StatusNoContent)
}
