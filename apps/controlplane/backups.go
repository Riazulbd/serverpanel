package main

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// siteHomeDir returns a site's home directory (/home/sites/<system_user>)
// from its recorded docroot (/home/sites/<system_user>/public per
// site.go's writeDefaultIndex layout) — the directory backup.run/
// backup.restore actually operate on, since a files/full backup covers the
// whole isolated home (php-fpm pool config aside), not just the web root.
func siteHomeDir(rec *siteRecord) string {
	return filepath.Dir(rec.Docroot)
}

// handleCreateBackup dispatches backup.run for one site and, only on
// success, persists a backups row — the same "only record what the agent
// actually did" pattern handleCreateSite uses, and for the same reason: a
// raw task result alone doesn't durably answer "what backups exist and
// where," which is what handleRestoreBackup and any future retention/
// scheduling feature need.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(siteID)
	if !ok || site.ServerID != serverID {
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
		writeErr(w, http.StatusBadRequest, "db_name is required for a db or full backup")
		return
	}

	// backup.run's 120s dispatch timeout already applies to potentially
	// large mysqldump + tar operations elsewhere in this codebase (see
	// handleDispatchTask); a full backup of a large site can legitimately
	// take longer, so this endpoint uses a wider bound than a routine task.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.run", map[string]any{
		"scope": req.Scope, "site_root": siteHomeDir(site), "db_name": req.DBName,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "backup.failed", "site="+site.Domain+" scope="+req.Scope+" error="+ev.Message)
		writeErr(w, http.StatusUnprocessableEntity, "backup.run failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		Scope     string    `json:"scope"`
		Path      string    `json:"path"`
		SizeBytes int64     `json:"size_bytes"`
		SHA256    string    `json:"sha256"`
		CreatedAt time.Time `json:"created_at"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup ran on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createBackup(serverID, siteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, "completed", req.DBName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup completed but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "site="+site.Domain+" scope="+req.Scope+" path="+result.Path+" sha256="+result.SHA256)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. It never accepts a caller-supplied archive path or database name
// — both come from the backups/sites rows the control plane itself wrote,
// which is what keeps a restore from being usable to reach an arbitrary
// path or database on the agent.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(backupID)
	if !ok || backup.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	params := map[string]any{"scope": backup.Scope, "path": backup.Path, "db_name": backup.DBName}
	if backup.Scope == "files" || backup.Scope == "full" {
		site, ok := a.store.getSite(backup.SiteID)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "the site this backup belongs to no longer exists")
			return
		}
		params["site_root"] = siteHomeDir(site)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "backup.restore_failed", "backup_id="+backupID+" error="+ev.Message)
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	var result struct {
		CheckpointPath string    `json:"checkpoint_path"`
		RestoredAt     time.Time `json:"restored_at"`
	}
	json.Unmarshal([]byte(ev.Detail), &result)

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" path="+backup.Path+" checkpoint="+result.CheckpointPath)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "restored",
		"backup_id":       backupID,
		"checkpoint_path": result.CheckpointPath,
	})
}
