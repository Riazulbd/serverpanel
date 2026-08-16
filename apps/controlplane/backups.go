package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run to the agent and, only on
// success, persists a backup record — the same dispatch-then-persist-on-
// success shape as handleCreateSite, for the same reason: a raw task
// result alone isn't enough to know a backup now exists on disk.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Scope  string `json:"scope"`
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Scope == "" {
		writeErr(w, http.StatusBadRequest, "scope is required")
		return
	}

	var siteRoot string
	if req.SiteID != "" {
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
		// docroot is the site's public webroot (<home>/public); back up
		// the whole site home directory, not just what's web-served.
		siteRoot = filepath.Dir(site.Docroot)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.run", map[string]any{
		"scope": req.Scope, "site_root": siteRoot, "db_name": req.DBName,
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

	rec, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, req.DBName, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "path="+result.Path+" scope="+result.Scope+" sha256="+result.SHA256)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. The archive path and checksum are read from the control plane's
// own record, never taken from the request body — a caller can restore
// *which* backup by ID, but cannot point the agent at an arbitrary path.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	rec, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	var siteRoot string
	if rec.SiteID != "" {
		site, ok := a.store.getSite(serverID, rec.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "the site this backup was taken from no longer exists")
			return
		}
		siteRoot = filepath.Dir(site.Docroot)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": rec.Scope, "site_root": siteRoot, "db_name": rec.DBName,
		"archive_path": rec.Path, "sha256": rec.SHA256,
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
		CheckpointPath string `json:"checkpoint_path"`
	}
	json.Unmarshal([]byte(ev.Detail), &result)

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" path="+rec.Path+" pre_restore_checkpoint="+result.CheckpointPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                 "restored",
		"pre_restore_checkpoint": result.CheckpointPath,
	})
}
