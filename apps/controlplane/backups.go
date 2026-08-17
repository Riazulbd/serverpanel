package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run to the agent and, only once the
// agent confirms the archive exists on disk (with its checksum), persists
// a backup record — same "don't record a fact the agent hasn't actually
// confirmed" pattern as handleCreateSite in sites.go.
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

	rec, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, "backup", req.SiteRoot, req.DBName)
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

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. The archive path and checksum sent to the agent always come from
// the control plane's own stored record, never from the request body — a
// caller cannot point this at an arbitrary path even if the endpoint
// itself is reached, because the agent independently re-verifies both the
// path (must be under its own backupBaseDir) and the checksum before
// touching anything live (see packages/capabilities/backup.go).
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupID")

	rec, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": rec.Scope, "site_root": rec.SiteRoot, "db_name": rec.DBName,
		"archive_path": rec.Path, "expected_sha256": rec.SHA256,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Scope                string `json:"scope"`
		RestoredFrom         string `json:"restored_from"`
		PreRestoreCheckpoint struct {
			Scope     string `json:"scope"`
			Path      string `json:"path"`
			SizeBytes int64  `json:"size_bytes"`
			SHA256    string `json:"sha256"`
		} `json:"pre_restore_checkpoint"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "restore ran on the agent but its result could not be parsed: "+err.Error())
		return
	}

	checkpoint, err := a.store.createBackup(serverID, rec.SiteID, result.PreRestoreCheckpoint.Scope,
		result.PreRestoreCheckpoint.Path, result.PreRestoreCheckpoint.SizeBytes, result.PreRestoreCheckpoint.SHA256,
		"checkpoint", rec.SiteRoot, rec.DBName)
	if err != nil {
		// The restore itself already succeeded on the agent; failing to
		// record the checkpoint here must not be reported as the restore
		// having failed, but it must not be silent either.
		a.store.log(serverID, actor, "backup.checkpoint_record_failed", err.Error())
	}
	a.store.markBackupRestored(rec.ID)
	a.store.log(serverID, actor, "backup.restored", "backup_id="+rec.ID+" scope="+rec.Scope)

	writeJSON(w, http.StatusOK, map[string]any{
		"restored_from":          rec,
		"pre_restore_checkpoint": checkpoint,
	})
}
