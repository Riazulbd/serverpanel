package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// handleCreateBackup dispatches backup.run to the agent and, only on
// success, persists a backup record — the same "only record what actually
// happened on the agent" pattern as handleCreateSite (see sites.go). A
// backup row therefore always corresponds to an archive that really exists
// on that server's disk, checksum included, which is what makes it safe
// for handleRestoreBackup to trust a stored backup's Path/SHA256 later
// without re-deriving them from caller input.
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

	params := map[string]any{"scope": req.Scope}
	if req.Scope == "db" || req.Scope == "full" {
		if req.DBName == "" {
			writeErr(w, http.StatusBadRequest, "db_name is required for scope "+req.Scope)
			return
		}
		params["db_name"] = req.DBName
	}
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for scope "+req.Scope)
			return
		}
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "site not found on this server")
			return
		}
		params["site_root"] = site.Docroot
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
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

	rec, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", "scope="+result.Scope+" path="+result.Path+" sha256="+result.SHA256)

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore for a previously recorded
// backup. The archive's path and checksum come from the stored record, not
// from the request body — a caller can only ever restore one of this
// server's own completed backups, never point the agent at an arbitrary
// path. The restore *target* (which database name, which site) is
// caller-supplied and may differ from where the backup originated, which
// is what makes "restore into a new application/database" possible, not
// just "restore in place".
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(serverID, backupID)
	if !ok {
		writeErr(w, http.StatusNotFound, "backup not found on this server")
		return
	}

	var req struct {
		SiteID string `json:"site_id"`
		DBName string `json:"db_name"`
	}
	json.NewDecoder(r.Body).Decode(&req) // both fields optional depending on scope; absence is validated below

	params := map[string]any{
		"scope":  backup.Scope,
		"path":   backup.Path,
		"sha256": backup.SHA256,
	}
	if backup.Scope == "db" || backup.Scope == "full" {
		if req.DBName == "" {
			writeErr(w, http.StatusBadRequest, "db_name is required to restore a "+backup.Scope+"-scope backup")
			return
		}
		params["db_name"] = req.DBName
	}
	if backup.Scope == "files" || backup.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required to restore a "+backup.Scope+"-scope backup")
			return
		}
		site, ok := a.store.getSite(serverID, req.SiteID)
		if !ok {
			writeErr(w, http.StatusNotFound, "target site not found on this server")
			return
		}
		params["site_root"] = site.Docroot
		params["owner_user"] = site.SystemUser
	}

	ctx, cancel := context.WithTimeout(r.Context(), 300*time.Second)
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

	a.store.log(serverID, actor, "backup.restored", "backup_id="+backupID+" scope="+backup.Scope+" detail="+ev.Detail)

	var result map[string]any
	json.Unmarshal([]byte(ev.Detail), &result)
	writeJSON(w, http.StatusOK, map[string]any{"backup_id": backupID, "result": result})
}
