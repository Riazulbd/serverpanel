package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// backupTaskTimeout is longer than the generic task-dispatch timeout
// (handleDispatchTask uses 120s) because a full-scope backup or restore of
// a real site (large uploads directory, big database dump) can legitimately
// take minutes; this is still bounded, not unlimited, per
// docs/ARCHITECTURE.md's "As built" note on synchronous task dispatch.
const backupTaskTimeout = 30 * time.Minute

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleCreateBackup dispatches backup.run to the agent and, only on
// success, persists the resulting archive's location/checksum — mirroring
// handleCreateSite's "only record what the agent actually did" pattern in
// sites.go. site_id (when scope needs files) is resolved to the site's home
// directory (the parent of its docroot) server-side, so the caller never
// supplies a raw filesystem path.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		Scope  string `json:"scope"`
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || (req.Scope != "db" && req.Scope != "files" && req.Scope != "full") {
		writeErr(w, http.StatusBadRequest, `scope must be one of "db", "files", "full"`)
		return
	}

	siteRoot := ""
	if req.SiteID != "" {
		site, ok := a.store.getSite(req.SiteID)
		if !ok || site.ServerID != serverID {
			writeErr(w, http.StatusBadRequest, "site not found on this server")
			return
		}
		siteRoot = filepath.Dir(site.Docroot)
	}
	if (req.Scope == "files" || req.Scope == "full") && siteRoot == "" {
		writeErr(w, http.StatusBadRequest, "site_id is required for scope files/full")
		return
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope db/full")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTaskTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.run", map[string]any{
		"scope": req.Scope, "site_root": siteRoot, "db_name": req.DBName,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "backup.failed", fmt.Sprintf("scope=%s site_id=%s: %s", req.Scope, req.SiteID, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "backup failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Scope     string `json:"scope"`
		Path      string `json:"path"`
		SizeBytes int64  `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup completed on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, req.DBName, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup completed on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", fmt.Sprintf("id=%s scope=%s size=%d", rec.ID, rec.Scope, rec.SizeBytes))
	writeJSON(w, http.StatusCreated, rec)
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. It always sends the checksum recorded at backup time as
// expected_sha256 (the agent refuses to restore if the on-disk archive no
// longer matches — see packages/capabilities/backup.go) and always uses the
// db_name/site that were backed up, never a caller-supplied override, so a
// restore can't be pointed at the wrong database.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	rec, ok := a.store.getBackup(backupID)
	if !ok || rec.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	siteRoot := ""
	if rec.SiteID != "" {
		if site, ok := a.store.getSite(rec.SiteID); ok {
			siteRoot = filepath.Dir(site.Docroot)
		} else {
			writeErr(w, http.StatusUnprocessableEntity, "this backup's site no longer exists")
			return
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTaskTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"backup_path": rec.Path, "scope": rec.Scope, "site_root": siteRoot,
		"db_name": rec.DBName, "expected_sha256": rec.SHA256,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "backup.restore_failed", fmt.Sprintf("backup_id=%s: %s", backupID, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "restore failed on the agent: "+ev.Message)
		return
	}
	a.store.log(serverID, actor, "backup.restored", fmt.Sprintf("backup_id=%s scope=%s", backupID, rec.Scope))
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored", "detail": ev.Detail})
}
