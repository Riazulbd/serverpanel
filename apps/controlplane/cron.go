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

// allowedCronBinaryNames mirrors packages/capabilities/cron.go's
// cronAllowedBinaries key set. It is validated here too so a bad request is
// rejected with a normal 400 before ever reaching the agent, rather than
// only being caught after a round trip to a connected server.
var allowedCronBinaryNames = map[string]bool{"php": true, "wp": true, "composer": true, "curl": true}

type cronJobRequest struct {
	Schedule string   `json:"schedule"`
	Binary   string   `json:"binary"`
	Args     []string `json:"args"`
	Enabled  *bool    `json:"enabled"`
}

func (req cronJobRequest) validate() error {
	if req.Schedule == "" {
		return fmt.Errorf("schedule is required")
	}
	if !allowedCronBinaryNames[req.Binary] {
		return fmt.Errorf("binary must be one of php, wp, composer, curl")
	}
	if len(req.Args) > 20 {
		return fmt.Errorf("too many arguments (max 20)")
	}
	return nil
}

func (a *apiServer) handleListCronJobs(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	if _, ok := a.store.getSite(serverID, siteID); !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	writeJSON(w, http.StatusOK, a.store.listCronJobs(serverID, siteID))
}

// handleCreateCronJob persists a new cron job and then syncs the site's
// full desired crontab to the agent. The record is saved before the sync
// is attempted (not after, unlike handleCreateBackup's
// dispatch-then-persist-on-success) because a cron job's source of truth
// is the control plane's own definition, not a result the agent computed —
// if the sync fails the job still exists and will be retried by the next
// mutation, or by an explicit POST .../cron/sync.
func (a *apiServer) handleCreateCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}

	var req cronJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	job, err := a.store.createCronJob(serverID, siteID, req.Schedule, req.Binary, req.Args, enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.created", fmt.Sprintf("site_id=%s job_id=%s schedule=%q binary=%s", siteID, job.ID, job.Schedule, job.Binary))

	if err := a.syncCronForSite(r.Context(), serverID, site, actor); err != nil {
		writeErr(w, http.StatusBadGateway, "cron job saved but could not be applied on the server yet: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, job)
}

func (a *apiServer) handleUpdateCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	jobID := r.PathValue("jobId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if existing, ok := a.store.getCronJob(serverID, jobID); !ok || existing.SiteID != siteID {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}

	var req cronJobRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := req.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	job, err := a.store.updateCronJob(serverID, jobID, req.Schedule, req.Binary, req.Args, enabled)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.updated", fmt.Sprintf("site_id=%s job_id=%s schedule=%q enabled=%v", siteID, job.ID, job.Schedule, job.Enabled))

	if err := a.syncCronForSite(r.Context(), serverID, site, actor); err != nil {
		writeErr(w, http.StatusBadGateway, "cron job saved but could not be applied on the server yet: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, job)
}

func (a *apiServer) handleDeleteCronJob(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	jobID := r.PathValue("jobId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if existing, ok := a.store.getCronJob(serverID, jobID); !ok || existing.SiteID != siteID {
		writeErr(w, http.StatusNotFound, "cron job not found")
		return
	}
	if err := a.store.deleteCronJob(serverID, jobID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.store.log(serverID, actor, "cron.deleted", fmt.Sprintf("site_id=%s job_id=%s", siteID, jobID))

	if err := a.syncCronForSite(r.Context(), serverID, site, actor); err != nil {
		writeErr(w, http.StatusBadGateway, "cron job deleted from the dashboard but could not be removed from the server yet: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleSyncCronJobs re-applies a site's current cron job set to the agent
// without changing any record, giving the dashboard an explicit retry path
// after a sync failure (network blip, agent briefly disconnected) instead
// of requiring the user to edit something just to trigger another attempt.
func (a *apiServer) handleSyncCronJobs(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")

	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return
	}
	if err := a.syncCronForSite(r.Context(), serverID, site, actor); err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "synced"})
}

// syncCronForSite pushes the site's full current *enabled* cron job list to
// the agent as one cron.sync call — the "recompute desired state, sync the
// whole thing" pattern used after every mutation, so the crontab on disk
// always converges to exactly what the dashboard shows regardless of which
// single field just changed. Disabled jobs are simply omitted from the
// payload rather than needing a separate agent-side "disable" capability.
func (a *apiServer) syncCronForSite(ctx context.Context, serverID string, site *siteRecord, actor string) error {
	jobs := a.store.listCronJobs(serverID, site.ID)
	payload := make([]map[string]any, 0, len(jobs))
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		payload = append(payload, map[string]any{
			"id": j.ID, "schedule": j.Schedule, "binary": j.Binary, "args": j.Args,
		})
	}

	dctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	ev, err := a.gw.dispatch(dctx, serverID, actor, capabilities.CapCronSync, map[string]any{
		"run_as_user": site.SystemUser, "jobs": payload,
	})
	if err != nil {
		return err
	}
	if ev.Status != proto.TaskSucceeded {
		return fmt.Errorf("%s", ev.Message)
	}
	return nil
}
