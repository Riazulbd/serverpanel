package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run and, only on success, persists a
// backup record — the same dispatch-then-persist shape as handleCreateSite
// (sites.go), and for the same reason: a raw task result alone doesn't mean
// a backup now exists as far as the dashboard/restore flow is concerned.
//
// For a files/full backup, site_root and system_user are deliberately never
// taken from the request body — they're derived from the caller-supplied
// site_id via the sites table, which this server already owns and trusts,
// rather than letting a client assert an arbitrary path to archive.
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
	if req.Scope != "db" && req.Scope != "files" && req.Scope != "full" {
		writeErr(w, http.StatusBadRequest, "scope must be one of db, files, full")
		return
	}

	var siteRoot, sysUser string
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for a files or full backup")
			return
		}
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found on this server")
			return
		}
		siteRoot = filepath.Dir(site.Docroot)
		sysUser = site.SystemUser
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for a db or full backup")
		return
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
		Path      string `json:"path"`
		SizeBytes int64  `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createBackup(serverID, req.SiteID, req.Scope, result.Path, result.SizeBytes, result.SHA256, req.DBName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	sysUserNote := ""
	if sysUser != "" {
		sysUserNote = " system_user=" + sysUser
	}
	a.store.log(serverID, actor, "backup.created", "scope="+req.Scope+" path="+result.Path+sysUserNote)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously-recorded
// backup. Like handleCreateBackup, the restore target for a files/full
// backup is derived from the backup's own recorded site_id rather than
// trusted from the request — a backup taken for one site can never be
// pointed at another site's directory through this endpoint. The agent's
// own pre-restore-checkpoint step (packages/capabilities/backup.go) is what
// actually protects the live data; on success here, that checkpoint is also
// recorded as a backup of its own so it shows up in the same list a
// future restore could target.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	var siteRoot, sysUser string
	if backup.Scope == "files" || backup.Scope == "full" {
		if backup.SiteID == "" {
			writeErr(w, http.StatusUnprocessableEntity, "this backup has no associated site to restore files into")
			return
		}
		site, ok := a.store.getSite(serverID, backup.SiteID)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "the site this backup belongs to no longer exists")
			return
		}
		siteRoot = filepath.Dir(site.Docroot)
		sysUser = site.SystemUser
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": backup.Scope, "backup_path": backup.Path, "expected_sha256": backup.SHA256,
		"db_name": backup.DBName, "site_root": siteRoot, "system_user": sysUser,
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
		CheckpointPath  string `json:"checkpoint_path"`
		CheckpointSHA   string `json:"checkpoint_sha256"`
		CheckpointSizeB int64  `json:"checkpoint_size_bytes"`
	}
	json.Unmarshal([]byte(ev.Detail), &result)

	var checkpoint *backupRecord
	if result.CheckpointPath != "" {
		checkpoint, _ = a.store.createBackup(serverID, backup.SiteID, backup.Scope, result.CheckpointPath, result.CheckpointSizeB, result.CheckpointSHA, backup.DBName)
	}

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+backup.Scope+" checkpoint="+result.CheckpointPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"restored_from": backup,
		"checkpoint":    checkpoint,
	})
}
