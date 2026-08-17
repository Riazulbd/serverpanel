package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// siteRootFor derives a site's isolated home directory from its recorded
// docroot (<site_root>/public — see packages/capabilities/site.go
// handleSiteCreate) rather than storing it as its own column, since it is
// always mechanically derivable and duplicating it would just be one more
// place for the two to drift apart.
func siteRootFor(site *siteRecord) string {
	return filepath.Dir(site.Docroot)
}

// handleCreateBackup dispatches backup.run for one site and, only on
// success, persists a backups row — the same "dispatch then persist the
// parsed result" pattern handleCreateSite uses, for the same reason: a raw
// task result alone doesn't tell the rest of the control plane a
// restorable backup now exists.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(siteID)
	if !ok || site.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "site not found on this server")
		return
	}

	var req struct {
		Scope  string `json:"scope"`
		DBName string `json:"db_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Scope == "" {
		writeErr(w, http.StatusBadRequest, "scope is required (db, files, or full)")
		return
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope db/full")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.run", map[string]any{
		"scope": req.Scope, "site_root": siteRootFor(site), "db_name": req.DBName,
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

	rec, err := a.store.createBackup(serverID, siteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, req.DBName, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "site="+siteID+" scope="+result.Scope+" path="+result.Path)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	writeJSON(w, http.StatusOK, a.store.listBackups(serverID, siteID))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. The agent always takes its own fresh pre-restore checkpoint of
// the destination before touching it (packages/capabilities/backup.go
// handleBackupRestore) — this handler's job on top of that is to record
// that checkpoint as a first-class backup row too, so "restore of a
// restore" is possible from the dashboard without any special case.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(backupID)
	if !ok || backup.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "backup not found on this server")
		return
	}

	var siteRoot, systemUser string
	if backup.SiteID != "" {
		site, ok := a.store.getSite(backup.SiteID)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "backup's site no longer exists; cannot determine restore destination")
			return
		}
		siteRoot = siteRootFor(site)
		systemUser = site.SystemUser
	}
	if (backup.Scope == "files" || backup.Scope == "full") && siteRoot == "" {
		writeErr(w, http.StatusUnprocessableEntity, "this backup has no associated site to restore files into")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": backup.Scope, "site_root": siteRoot, "system_user": systemUser,
		"db_name": backup.DBName, "archive_path": backup.Path, "expected_sha256": backup.SHA256,
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
		CheckpointPath      string `json:"checkpoint_path"`
		CheckpointSHA       string `json:"checkpoint_sha256"`
		CheckpointSizeBytes int64  `json:"checkpoint_size_bytes"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "restore succeeded on the agent but its result could not be parsed: "+err.Error())
		return
	}

	checkpoint, err := a.store.createBackup(serverID, backup.SiteID, backup.Scope, result.CheckpointPath,
		result.CheckpointSizeBytes, result.CheckpointSHA, backup.DBName, "pre_restore_checkpoint")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "restore succeeded but its pre-restore checkpoint could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.restored", "backup="+backupID+" checkpoint="+checkpoint.ID)

	writeJSON(w, http.StatusOK, map[string]any{
		"restored_from":          backup,
		"pre_restore_checkpoint": checkpoint,
	})
}
