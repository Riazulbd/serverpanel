package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/riazulbd/serverpanel/packages/proto"
)

// backupTaskTimeout is longer than the general task timeout used elsewhere
// (sites.go, http.go's generic dispatch) because backup.run/backup.restore
// can involve a full mysqldump and/or tar of a site's files, which on a
// large site can genuinely take minutes — not the few seconds a
// service-control or file-manager call takes.
const backupTaskTimeout = 300 * time.Second

// handleCreateBackup dispatches backup.run and, only on success, persists a
// backup record — the same "only write the row once the agent has
// confirmed success" split used by handleCreateSite (sites.go), so the
// backups table never claims an archive exists that the agent failed to
// produce.
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

	siteRoot := ""
	if req.SiteID != "" {
		site, ok := a.store.getSite(req.SiteID)
		if !ok || site.ServerID != serverID {
			writeErr(w, http.StatusNotFound, "site not found on this server")
			return
		}
		siteRoot = site.Docroot
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
	a.store.log(serverID, actor, "backup.created", fmt.Sprintf("id=%s scope=%s path=%s size=%d", rec.ID, rec.Scope, rec.Path, rec.SizeBytes))

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore using the archive path and
// checksum recorded at backup-creation time — never a client-supplied path
// or checksum — so a restore can only ever target an archive this control
// plane itself created and verified, matching the same trust boundary
// backup.restore's own checksum-verification step enforces on the agent
// side (see packages/capabilities/backup.go).
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	rec, ok := a.store.getBackup(backupID)
	if !ok || rec.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "backup not found on this server")
		return
	}

	var req struct {
		DBName string `json:"db_name"`
	}
	json.NewDecoder(r.Body).Decode(&req) // optional body; db_name is only needed for a db/full scope restore

	siteRoot := ""
	if rec.SiteID != "" {
		if site, ok := a.store.getSite(rec.SiteID); ok {
			siteRoot = site.Docroot
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), backupTaskTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": rec.Scope, "archive_path": rec.Path, "expected_sha256": rec.SHA256,
		"site_root": siteRoot, "db_name": req.DBName,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "backup.restored", fmt.Sprintf("id=%s scope=%s path=%s", rec.ID, rec.Scope, rec.Path))
	writeJSON(w, http.StatusOK, map[string]string{"status": "restored", "detail": ev.Detail})
}
