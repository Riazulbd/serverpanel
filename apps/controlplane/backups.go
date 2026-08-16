package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// backupTaskTimeout is generous: a full-scope backup/restore on a large
// site involves mysqldump/mysql plus tar/cp over the whole site directory,
// which can legitimately take minutes on a large WordPress install — the
// same reasoning as handleCreateSite's 120s timeout, just longer because
// this dispatch does substantially more I/O.
const backupTaskTimeout = 15 * time.Minute

// resolveSiteRoot returns the site's home directory (the parent of its web
// docroot, e.g. docroot=/home/sites/site_x/public -> /home/sites/site_x) —
// the directory backup.run/backup.restore expect as site_root so a backup
// captures everything under the site's home, not just its web-served
// subtree.
func resolveSiteRoot(a *apiServer, siteID string) (string, bool) {
	site, ok := a.store.getSite(siteID)
	if !ok {
		return "", false
	}
	return filepath.Dir(site.Docroot), true
}

// handleCreateBackup dispatches backup.run to the agent and, only on
// success, persists a backup record — same "dispatch first, persist only
// on a real success" shape as handleCreateSite, and for the same reason:
// the JSON detail backup.run returns (path/size/checksum) is the one place
// those facts are known, so there's nothing meaningful to persist earlier.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Scope  string `json:"scope"`
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Scope == "" {
		writeErr(w, http.StatusBadRequest, "scope is required (db, files, or full)")
		return
	}

	params := map[string]any{"scope": req.Scope, "db_name": req.DBName}
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for scope files or full")
			return
		}
		siteRoot, ok := resolveSiteRoot(a, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
		params["site_root"] = siteRoot
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope db or full")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTaskTimeout)
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
		Path      string `json:"path"`
		SizeBytes int64  `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createBackup(serverID, req.SiteID, req.DBName, req.Scope, result.Path, result.SizeBytes, result.SHA256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "scope="+req.Scope+" path="+result.Path)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. The archive path, checksum, scope, and (for db/full) database
// name all come from the stored backup record rather than the request
// body — a caller can only restore a backup this control plane itself
// created and recorded, never an arbitrary agent-side file path.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	rec, ok := a.store.getBackup(backupID)
	if !ok || rec.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	params := map[string]any{
		"scope": rec.Scope, "archive_path": rec.Path, "expected_sha256": rec.SHA256, "db_name": rec.DBName,
	}
	if rec.Scope == "files" || rec.Scope == "full" {
		if rec.SiteID == "" {
			writeErr(w, http.StatusUnprocessableEntity, "backup record has no associated site to restore files into")
			return
		}
		siteRoot, ok := resolveSiteRoot(a, rec.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site associated with this backup no longer exists")
			return
		}
		params["site_root"] = siteRoot
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTaskTimeout)
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
	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+rec.Scope)

	writeJSON(w, http.StatusOK, ev)
}
