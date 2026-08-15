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

// handleRunBackup dispatches backup.run to the agent and, only on success,
// persists a backup record — the same "dispatch, parse the JSON detail,
// persist" shape as handleCreateSite (see sites.go's doc comment). Before
// this handler, backup.run's dispatch went unrecorded: the backups table
// existed but nothing wrote a row into it (see docs/OPERATIONS.md history).
func (a *apiServer) handleRunBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")

	var req struct {
		SiteID string `json:"site_id"`
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

	params := map[string]any{"scope": req.Scope}
	if req.Scope == "db" || req.Scope == "full" {
		if req.DBName == "" {
			writeErr(w, http.StatusBadRequest, "db_name is required for scope db or full")
			return
		}
		params["db_name"] = req.DBName
	}
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for scope files or full")
			return
		}
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
		params["site_root"] = filepath.Dir(site.Docroot)
	}

	// Backups of real sites/databases can legitimately take minutes; a much
	// longer bound than the default 120s task-dispatch timeout used
	// elsewhere.
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
		Path      string `json:"path"`
		SizeBytes int64  `json:"size_bytes"`
		SHA256    string `json:"sha256"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup ran on the agent but its result could not be parsed: "+err.Error())
		return
	}

	rec, err := a.store.createBackup(serverID, req.SiteID, req.Scope, result.Path, result.SizeBytes, result.SHA256, req.DBName, "completed")
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup ran but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", fmt.Sprintf("backup_id=%s scope=%s path=%s sha256=%s", rec.ID, rec.Scope, rec.Path, rec.SHA256))

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.listBackups(r.PathValue("id")))
}

// handleRestoreBackup dispatches backup.restore for a previously-recorded
// backup. It derives site_root/db_name from the stored backup record (and,
// for files/full, the site record it belongs to) rather than trusting
// anything the caller supplies in the request body — a backup can only ever
// be restored to the site/database it actually came from, or to a site of
// the same ID if it's been recreated, which keeps "restore" from becoming
// an arbitrary-write-to-any-path primitive over the API.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	params := map[string]any{"scope": backup.Scope, "path": backup.Path, "sha256": backup.SHA256}
	if backup.Scope == "db" || backup.Scope == "full" {
		if backup.DBName == "" {
			writeErr(w, http.StatusUnprocessableEntity, "this backup has no recorded database name and cannot restore its db scope")
			return
		}
		params["db_name"] = backup.DBName
	}
	if backup.Scope == "files" || backup.Scope == "full" {
		if backup.SiteID == "" {
			writeErr(w, http.StatusUnprocessableEntity, "this backup is not associated with a site and cannot restore its files scope")
			return
		}
		site, ok := a.store.getSite(serverID, backup.SiteID)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "the site this backup belongs to no longer exists on this server")
			return
		}
		params["site_root"] = filepath.Dir(site.Docroot)
	}

	// Restores extract, and possibly mysqldump *and* mysql-import, on top
	// of the archive read — generously bounded for the same reason as
	// handleRunBackup above.
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
		Scope               string    `json:"scope"`
		RestoredDatabase    bool      `json:"restored_database"`
		RestoredFiles       bool      `json:"restored_files"`
		CheckpointPath      string    `json:"checkpoint_path"`
		CheckpointSizeBytes int64     `json:"checkpoint_size_bytes"`
		CheckpointSHA256    string    `json:"checkpoint_sha256"`
		CheckpointError     string    `json:"checkpoint_error"`
		RestoredAt          time.Time `json:"restored_at"`
	}
	if err := json.Unmarshal([]byte(ev.Detail), &result); err != nil {
		writeErr(w, http.StatusInternalServerError, "restore ran on the agent but its result could not be parsed: "+err.Error())
		return
	}

	var checkpoint *backupRecord
	if result.CheckpointPath != "" {
		checkpoint, err = a.store.createBackup(serverID, backup.SiteID, backup.Scope, result.CheckpointPath,
			result.CheckpointSizeBytes, result.CheckpointSHA256, backup.DBName, "completed")
		if err != nil {
			// The checkpoint archive exists on the agent's disk either way;
			// failing to record it here is a bookkeeping problem, not a
			// reason to report the (already-successful) restore as failed.
			a.store.log(serverID, actor, "backup.checkpoint_record_failed", err.Error())
		}
	}

	detail := fmt.Sprintf("backup_id=%s scope=%s restored_database=%v restored_files=%v",
		backup.ID, backup.Scope, result.RestoredDatabase, result.RestoredFiles)
	if result.CheckpointError != "" {
		detail += fmt.Sprintf(" checkpoint_error=%q", result.CheckpointError)
	}
	a.store.log(serverID, actor, "backup.restored", detail)

	writeJSON(w, http.StatusOK, map[string]any{
		"result":     result,
		"checkpoint": checkpoint,
	})
}
