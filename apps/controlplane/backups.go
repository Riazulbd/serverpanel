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
// success, persists a backups row — the same "dispatch first, only record
// on confirmed success" pattern handleCreateSite uses (sites.go), for the
// same reason: a raw task result alone doesn't tell the dashboard a backup
// now exists to be listed/restored, and the JSON detail backup.run returns
// (packages/capabilities/backup.go backupResult) is the one place that
// fact is expressed.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Scope  string `json:"scope"`
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Scope != "db" && req.Scope != "files" && req.Scope != "full" {
		writeErr(w, http.StatusBadRequest, "scope must be one of db, files, full")
		return
	}

	params := map[string]any{"scope": req.Scope, "db_name": req.DBName}
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for scope=files or scope=full")
			return
		}
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found on this server")
			return
		}
		params["site_root"] = filepath.Dir(site.Docroot) // site's home dir, e.g. /home/sites/site_example_com
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope=db or scope=full")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.run", params)
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

	backup, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "scope="+result.Scope+" path="+result.Path+" sha256="+result.SHA256)

	writeJSON(w, http.StatusCreated, backup)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. Restore is currently only supported back onto the same server
// that produced the backup: the recorded path only exists on that agent's
// local disk (local storage is the only backend Phase 1 ships — see
// docs/OPERATIONS.md "Backup and restore"), so a cross-server restore
// isn't possible until a remote (S3-compatible) storage backend exists.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found on this server")
		return
	}

	var req struct {
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	json.NewDecoder(r.Body).Decode(&req) // request body is optional; defaults below cover the common case

	siteID := req.SiteID
	if siteID == "" {
		siteID = backup.SiteID
	}

	params := map[string]any{
		"backup_path": backup.Path,
		"scope":       backup.Scope,
		"db_name":     req.DBName,
		"sha256":      backup.SHA256,
	}
	if backup.Scope == "files" || backup.Scope == "full" {
		if siteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required to restore a files or full backup")
			return
		}
		site, ok := a.store.getSite(serverID, siteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found on this server")
			return
		}
		params["site_root"] = filepath.Dir(site.Docroot)
	}
	if (backup.Scope == "db" || backup.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required to restore a db or full backup")
		return
	}

	// Restoring can mean extracting a large archive and (for db/full) a
	// full mysql import, plus its own pre-restore checkpoint backup — all
	// slower than a typical task, hence the longer timeout than
	// handleDispatchTask's default.
	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+backup.Scope+" detail="+ev.Detail)

	var result map[string]any
	json.Unmarshal([]byte(ev.Detail), &result)
	writeJSON(w, http.StatusOK, result)
}
