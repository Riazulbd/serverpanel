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

// backupCapabilityResult mirrors packages/capabilities backupResult — the
// JSON detail backup.run's TaskEvent carries back.
type backupCapabilityResult struct {
	Scope     string    `json:"scope"`
	Path      string    `json:"path"`
	SizeBytes int64     `json:"size_bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

// siteRootFor returns the managed home directory a backup/restore
// capability call should use as site_root — always the site's system-user
// home directory (/home/sites/<system_user>), never the docroot subpath, so
// a backup captures everything under the isolated user's home, not just the
// webroot.
func siteRootFor(rec *siteRecord) string {
	return filepath.Join("/home/sites", rec.SystemUser)
}

// handleCreateBackup dispatches backup.run to the agent and, only on
// success, persists a backups row — the same "don't record what the agent
// didn't actually do" rule handleCreateSite follows.
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
	if req.Scope != "db" && req.Scope != "files" && req.Scope != "full" {
		writeErr(w, http.StatusBadRequest, "scope must be one of db, files, full")
		return
	}

	var siteRoot string
	if req.Scope == "files" || req.Scope == "full" {
		if req.SiteID == "" {
			writeErr(w, http.StatusBadRequest, "site_id is required for scope files/full")
			return
		}
		site, ok := a.store.getSite(req.SiteID)
		if !ok || site.ServerID != serverID {
			writeErr(w, http.StatusNotFound, "site not found on this server")
			return
		}
		siteRoot = siteRootFor(site)
	}
	if (req.Scope == "db" || req.Scope == "full") && req.DBName == "" {
		writeErr(w, http.StatusBadRequest, "db_name is required for scope db/full")
		return
	}

	// Backup archives (a full mysqldump plus, for "full", an entire site
	// tree) can legitimately take longer than the 120s bound used for
	// interactive tasks elsewhere; this endpoint's own timeout is longer to
	// match, matching the "long-running operations get their own budget"
	// principle rather than an arbitrary shared constant.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
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

	rec, err := a.store.createBackup(serverID, req.SiteID, result.Scope, result.Path, result.SizeBytes, result.SHA256, req.DBName)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "backup archive was created on the agent but could not be recorded: "+err.Error())
		return
	}
	a.store.log(serverID, actor, "backup.created", fmt.Sprintf("id=%s scope=%s size_bytes=%d", rec.ID, rec.Scope, rec.SizeBytes))

	writeJSON(w, http.StatusCreated, rec)
}

func (a *apiServer) handleListBackups(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	writeJSON(w, http.StatusOK, a.store.listBackups(id))
}

// handleRestoreBackup dispatches backup.restore to the agent using the
// checksum recorded at backup time — the control plane never lets a caller
// supply their own expected_sha256, which is what makes "restore refuses to
// run against an unverified archive" (packages/capabilities/backup.go)
// actually mean something: the value it's checked against comes from this
// server's own database, not from the request body.
func (a *apiServer) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	backupID := r.PathValue("backupId")

	backup, ok := a.store.getBackup(backupID)
	if !ok || backup.ServerID != serverID {
		writeErr(w, http.StatusNotFound, "backup not found on this server")
		return
	}

	var siteRoot string
	if backup.Scope == "files" || backup.Scope == "full" {
		if backup.SiteID == "" {
			writeErr(w, http.StatusUnprocessableEntity, "backup has no associated site to restore files into")
			return
		}
		site, ok := a.store.getSite(backup.SiteID)
		if !ok || site.ServerID != serverID {
			writeErr(w, http.StatusUnprocessableEntity, "the site this backup belongs to no longer exists on this server")
			return
		}
		siteRoot = siteRootFor(site)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Minute)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, serverID, actor, "backup.restore", map[string]any{
		"scope": backup.Scope, "site_root": siteRoot, "db_name": backup.DBName,
		"backup_path": backup.Path, "expected_sha256": backup.SHA256,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "backup.restore failed on the agent: "+ev.Message)
		return
	}

	a.store.log(serverID, actor, "backup.restored", "id="+backup.ID+" scope="+backup.Scope)
	writeJSON(w, http.StatusOK, ev)
}
