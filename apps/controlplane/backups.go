package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/capabilities"
	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run for one site and, only on
// success, persists the resulting backup record — the same
// dispatch-then-persist-on-success pattern handleCreateSite uses, for the
// same reason: a raw task result alone doesn't establish that a durable,
// restorable backup now exists.
func (a *apiServer) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
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
	if req.Scope != "db" && req.Scope != "files" && req.Scope != "full" {
		writeErr(w, http.StatusBadRequest, "scope must be one of db, files, full")
		return
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope db or full")
		return
	}

	// backup.run's 120s default dispatch timeout is too tight for a large
	// site's file archive or database dump; backups get a longer budget.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapBackupRun, map[string]any{
		"scope": req.Scope, "site_root": site.Docroot, "db_name": req.DBName,
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
		writeErr(w, http.StatusInternalServerError, "backup completed on the agent but its result could not be parsed: "+err.Error())
		return
	}

	backup, err := a.store.createBackup(serverID, siteID, result.Scope, result.Path, req.DBName, result.SizeBytes, result.SHA256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup completed on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", fmt.Sprintf("site_id=%s scope=%s path=%s size_bytes=%d", siteID, result.Scope, result.Path, result.SizeBytes))

	writeJSON(w, http.StatusCreated, backup)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listBackups(serverID, siteID))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. It is deliberately a POST with an explicit confirmation
// requirement enforced client-side (see web/index.html) and, server-side,
// requires the caller to echo back the backup's own id in the URL — there
// is no "restore the latest backup" shortcut that could act on the wrong
// archive.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found")
		return
	}

	params := map[string]any{
		"archive_path":    backup.Path,
		"scope":           backup.Scope,
		"db_name":         backup.DBName,
		"expected_sha256": backup.SHA256,
	}
	if backup.Scope == "files" || backup.Scope == "full" {
		site, ok := a.store.getSite(serverID, backup.SiteID)
		if !ok {
			writeErr(w, http.StatusUnprocessableEntity, "the site this backup belongs to no longer exists on this server")
			return
		}
		params["site_root"] = site.Docroot
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, capabilities.CapBackupRestore, params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		a.store.log(serverID, actor, "backup.restore_failed", fmt.Sprintf("backup_id=%s: %s", backupID, ev.Message))
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "backup.restored", fmt.Sprintf("backup_id=%s site_id=%s scope=%s detail=%s", backupID, backup.SiteID, backup.Scope, ev.Detail))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(ev.Detail))
}
