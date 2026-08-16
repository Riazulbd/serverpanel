package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run and, only on success, persists a
// backup record — the same "dispatch, then record the durable fact"
// pattern as handleCreateSite (sites.go), and for the same reason: a raw
// task result isn't itself a fact this control plane can later restore
// from by ID, only the parsed archive path + checksum is.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Scope    string `json:"scope"`
		SiteID   string `json:"site_id"`
		SiteRoot string `json:"site_root"`
		DBName   string `json:"db_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Scope == "" {
		writeErr(w, http.StatusBadRequest, "scope is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.run", map[string]any{
		"scope": req.Scope, "site_root": req.SiteRoot, "db_name": req.DBName,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "backup.run failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Scope     string `json:"scope"`
		Path      string `json:"path"`
		SizeBytes int64  `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "scope="+result.Scope+" path="+result.Path+" sha256="+result.SHA256)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore against a backup this
// control plane already has a recorded path and checksum for — the caller
// only ever names a backup by its ID plus where to restore it to, never a
// filesystem path directly, which is what makes "restore a backup you
// didn't create/aren't authorized to see" impossible at this layer (see
// store.getBackup, scoped to server_id).
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	rec, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	var req struct {
		RestoreSiteRoot   string `json:"restore_site_root"`
		RestoreSystemUser string `json:"restore_system_user"`
		RestoreDBName     string `json:"restore_db_name"`
		SkipCheckpoint    bool   `json:"skip_checkpoint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"archive_path":        rec.Path,
		"expected_sha256":     rec.SHA256,
		"scope":               rec.Scope,
		"restore_site_root":   req.RestoreSiteRoot,
		"restore_system_user": req.RestoreSystemUser,
		"restore_db_name":     req.RestoreDBName,
		"skip_checkpoint":     req.SkipCheckpoint,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+rec.Scope)
	writeJSON(w, http.StatusOK, json.RawMessage(ev.Detail))
}
