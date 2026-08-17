package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run to the agent and, only on
// success, persists a backup record — the same "dispatch then record, never
// the reverse" shape as handleCreateSite (sites.go), for the same reason: a
// raw task result isn't itself a durable fact the dashboard can list later.
//
// The caller identifies what to back up by site_id (looked up server-side
// for its home_dir, never trusted from the request body) plus an optional
// db_name when scope is "db" or "full" — sites don't have an associated
// database recorded anywhere yet (db.create is a standalone capability), so
// db_name has to come from the caller until that changes.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
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

	var siteRoot string
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for scope files/full")
			return
		}
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found")
			return
		}
		siteRoot = site.HomeDir
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	params := map[string]any{"scope": req.Scope, "site_root": siteRoot, "db_name": req.DBName}
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
		writeErr(w, http.StatusInternalServerError, "backup ran but its result could not be parsed: "+err.Error())
		return
	}

	paramsJSON, _ := json.Marshal(params)
	backup, err := a.store.createBackup(serverID, req.SiteID, req.Scope, result.Path, result.SizeBytes, result.SHA256, "completed", "manual", string(paramsJSON))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup ran but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "scope="+req.Scope+" path="+result.Path)

	writeJSON(w, http.StatusCreated, backup)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.URL.Query().Get("site_id")
	writeJSON(w, http.StatusOK, a.store.listBackups(serverID, siteID))
}

// handleRestoreBackup dispatches backup.restore using exactly the
// scope/site_root/db_name the chosen backup was originally taken with
// (recovered from its stored params_json), so the caller only ever has to
// supply a backup ID and, optionally, opt out of the default pre-restore
// checkpoint. On success, a checkpoint backup the agent took automatically
// is itself persisted as a listable/restorable backup record — a failed
// restore attempt should never be a dead end.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	var origParams struct {
		Scope    string `json:"scope"`
		SiteRoot string `json:"site_root"`
		DBName   string `json:"db_name"`
	}
	if err := json.Unmarshal([]byte(backup.ParamsJSON), &origParams); err != nil {
		writeErr(w, http.StatusInternalServerError, "backup record has no recoverable parameters: "+err.Error())
		return
	}

	var req struct {
		Checkpoint *bool `json:"checkpoint"`
	}
	json.NewDecoder(r.Body).Decode(&req) // optional body; absence/parse failure just keeps defaults
	checkpoint := true
	if req.Checkpoint != nil {
		checkpoint = *req.Checkpoint
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"path": backup.Path, "scope": origParams.Scope, "site_root": origParams.SiteRoot,
		"db_name": origParams.DBName, "checkpoint": checkpoint,
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

	var checkpointBackup *backupRecord
	if result.CheckpointPath != "" {
		checkpointBackup, err = a.store.createBackup(serverID, backup.SiteID, origParams.Scope, result.CheckpointPath, 0, "", "completed", "checkpoint", backup.ParamsJSON)
		if err != nil {
			// The restore itself already succeeded; failing to record the
			// checkpoint is logged but must not turn a successful restore
			// into an error response.
			a.store.log(serverID, actor, "backup.checkpoint_record_failed", err.Error())
		}
	}

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+origParams.Scope)
	writeJSON(w, http.StatusOK, map[string]any{
		"restored_from": backup,
		"checkpoint":    checkpointBackup,
	})
}
