package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// backupCapabilityResult mirrors packages/capabilities/backup.go's
// backupResult JSON shape — the control plane parses it out of a
// successful backup.run TaskEvent's Detail to persist a backups row, the
// same "capability result -> control-plane record" pattern handleCreateSite
// uses for site.create.
type backupCapabilityResult struct {
	Scope     string `json:"scope"`
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// restoreCapabilityResult mirrors backup.restore's JSON result.
type restoreCapabilityResult struct {
	CheckpointPath      string `json:"checkpoint_path"`
	CheckpointSizeBytes int64  `json:"checkpoint_size_bytes"`
	CheckpointSHA256    string `json:"checkpoint_sha256"`
}

// handleCreateBackup dispatches backup.run and, only on success, persists a
// backups row recording the archive's path and checksum — the checksum is
// what handleRestoreBackup later hands back to the agent as expected_sha256,
// so a restore always verifies against what was actually produced, not
// against a value the dashboard or caller could get wrong.
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

	siteRoot := req.SiteRoot
	if req.SiteID != "" {
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
		// site.create lays out a site as /home/sites/<user>/public (docroot)
		// under /home/sites/<user> (the site's home) — backing up the home
		// directory, not just the public webroot, captures anything an app
		// stores alongside it (e.g. a Laravel .env one level up).
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

	var result backupCapabilityResult
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup completed on the agent but its result could not be parsed: "+err.Error())
		return
	}

	backup, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup completed on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "scope="+result.Scope+" path="+result.Path+" sha256="+result.SHA256)

	writeJSON(w, http.StatusCreated, backup)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup looks up the backups row addressed by {backupId}
// (never trusting a caller-supplied path/checksum directly) and dispatches
// backup.restore with that archive's real path and checksum. On success it
// also persists the pre-restore checkpoint the agent took as its own
// backups row (status "checkpoint"), so restoring a bad restore is just
// another restore, not a manual recovery exercise.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	var req struct {
		SiteRoot  string `json:"site_root"`
		DBName    string `json:"db_name"`
		OwnerUser string `json:"owner_user"`
	}
	json.NewDecoder(r.Body).Decode(&req) // optional body; zero value is fine if backup.SiteID resolves everything

	siteRoot, ownerUser := req.SiteRoot, req.OwnerUser
	if backup.SiteID != "" {
		if site, ok := a.store.getSite(serverID, backup.SiteID); ok {
			siteRoot = filepath.Dir(site.Docroot)
			ownerUser = site.SystemUser
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": backup.Scope, "archive_path": backup.Path, "expected_sha256": backup.SHA256,
		"site_root": siteRoot, "db_name": req.DBName, "owner_user": ownerUser,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "backup.restore_failed", "backup_id="+backupID+" message="+ev.Message)
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	var result restoreCapabilityResult
	checkpoint := (*backupRecord)(nil)
	if err := json.Unmarshal([]byte(ev.Detail), &result); err == nil && result.CheckpointPath != "" {
		checkpoint, _ = a.store.createBackup(serverID, backup.SiteID, backup.Scope, result.CheckpointPath, result.CheckpointSizeBytes, result.CheckpointSHA256, "checkpoint")
	}

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+backup.Scope)

	writeJSON(w, http.StatusOK, map[string]any{
		"restored_from": backup,
		"checkpoint":    checkpoint,
	})
}
