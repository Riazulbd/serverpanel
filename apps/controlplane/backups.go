package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// backupSiteRoot derives the site's isolated home directory from its
// docroot. Sites are always created with docroot == home/"public" (see
// packages/capabilities/site.go handleSiteCreate), so this is a one-line
// derivation rather than a second stored field duplicating the same fact.
func backupSiteRoot(site *siteRecord) string {
	return filepath.Dir(site.Docroot)
}

// handleCreateBackup dispatches backup.run for a specific site and, only on
// success, persists a backup record — the same "dispatch then persist the
// agent's typed result" split used by handleCreateSite, for the same
// reason: a raw task result alone doesn't tell the control plane a backup
// now exists on disk.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site := a.findSite(serverID, siteID)
	if site == nil {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req struct {
		Scope  string `json:"scope"`
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
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope db or full")
		return
	}

	params := map[string]any{"scope": req.Scope, "db_name": req.DBName}
	if req.Scope == "files" || req.Scope == "full" {
		params["site_root"] = backupSiteRoot(site)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
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

	backup, err := a.store.createBackup(serverID, siteID, result.Scope, result.Path, result.SizeBytes, result.SHA256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "site="+siteID+" scope="+result.Scope+" path="+result.Path)

	writeJSON(w, http.StatusCreated, backup)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. The stored sha256 (never a value from the request body) is what
// gets sent to the agent to verify against, and restoring a files/full
// backup requires the target site to still be known to the control plane
// so the agent can be told which system user to chown the restored files
// to — the same isolation boundary every other site-scoped capability
// relies on.
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
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	siteID := req.SiteID
	if siteID == "" {
		siteID = backup.SiteID
	}

	params := map[string]any{"scope": backup.Scope, "path": backup.Path, "sha256": backup.SHA256, "db_name": req.DBName}
	if backup.Scope == "files" || backup.Scope == "full" {
		site := a.findSite(serverID, siteID)
		if site == nil {
			writeErr(w, http.StatusBadRequest, "restoring a files/full backup requires a known site_id")
			return
		}
		params["site_root"] = backupSiteRoot(site)
		params["system_user"] = site.SystemUser
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
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

	var result struct {
		Scope                 string `json:"scope"`
		DatabaseRestored      bool   `json:"database_restored"`
		FilesRestored         bool   `json:"files_restored"`
		PreRestoreArchive     string `json:"pre_restore_archive"`
		PreRestoreArchiveSize int64  `json:"pre_restore_archive_size_bytes"`
		PreRestoreArchiveSHA  string `json:"pre_restore_archive_sha256"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "restore ran on the agent but its result could not be parsed: "+err.Error())
		return
	}

	var checkpoint *backupRecord
	if result.PreRestoreArchive != "" {
		checkpoint, err = a.store.createBackup(serverID, siteID, backup.Scope, result.PreRestoreArchive,
			result.PreRestoreArchiveSize, result.PreRestoreArchiveSHA)
		if err != nil {
			// The restore itself already succeeded; failing to record the
			// checkpoint shouldn't be reported as a restore failure, but it
			// must still be visible in the audit trail.
			a.store.log(serverID, actor, "backup.checkpoint_record_failed", err.Error())
		}
	}

	a.store.log(serverID, actor, "backup.restored", "backup="+backupID+" site="+siteID+" scope="+backup.Scope)

	writeJSON(w, http.StatusOK, map[string]any{
		"database_restored":      result.DatabaseRestored,
		"files_restored":         result.FilesRestored,
		"pre_restore_checkpoint": checkpoint,
	})
}

func (a *apiServer) findSite(serverID, siteID string) *siteRecord {
	for _, s := range a.store.listSites(serverID) {
		if s.ID == siteID {
			return s
		}
	}
	return nil
}
