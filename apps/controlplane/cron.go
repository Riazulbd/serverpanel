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

// cronDispatchTimeout is generous relative to site.create's 120s default:
// editing a crontab is normally instant, but it still goes through a live
// agent round trip, and a slow/loaded agent shouldn't make cron management
// flaky.
const cronDispatchTimeout = 30 * time.Second

// cronJob mirrors packages/capabilities/cron.go's cronEntry — kept as its
// own type here (rather than importing the unexported capabilities type)
// since it's the control plane's public API response shape, not an internal
// implementation detail shared with the agent.
type cronJob struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"`
	Enabled  bool   `json:"enabled"`
}

// resolveCronSite is the entry point every cron endpoint below starts with.
// It is also the actual authorization/ownership boundary for cron
// management, not just a lookup: the crontab "owner" the agent ever touches
// is site.SystemUser, read from this control plane's own stored site
// record for the exact server+site the URL names — never a system_user
// value taken from client-supplied request JSON. A caller can therefore
// never point a cron.* dispatch at a user they don't manage; the worst a
// malformed/adversarial request can do is name a server/site pair that
// doesn't resolve, which 404s here before anything is dispatched.
func (a *apiServer) resolveCronSite(w http.ResponseWriter, r *http.Request) (*siteRecord, bool) {
	serverID := r.PathValue("id")
	siteID := r.PathValue("siteId")
	site, ok := a.store.getSite(serverID, siteID)
	if !ok {
		writeErr(w, http.StatusNotFound, "site not found")
		return nil, false
	}
	return site, true
}

// resolveCronSchedule turns a request's schedule_preset/schedule pair into
// one concrete cron expression: a known preset name wins if given, otherwise
// the free-form custom expression is used as-is. The actual field-by-field
// syntax/range validation happens once, agent-side, in
// packages/capabilities/cron.go's validateCronSchedule — this only resolves
// which string gets validated.
func resolveCronSchedule(preset, custom string) (string, error) {
	if preset != "" {
		expr, ok := capabilities.CronPresets[preset]
		if !ok {
			return "", fmt.Errorf("unknown schedule_preset %q", preset)
		}
		return expr, nil
	}
	if custom == "" {
		return "", fmt.Errorf("schedule (or schedule_preset) is required")
	}
	return custom, nil
}

func (a *apiServer) handleListCron(w http.ResponseWriter, r *http.Request) {
	site, ok := a.resolveCronSite(w, r)
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), cronDispatchTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, site.ServerID, sessionFromContext(r.Context()).Email, capabilities.CapCronList, map[string]any{
		"system_user": site.SystemUser,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.list failed on the agent: "+ev.Message)
		return
	}

	var jobs []cronJob
	if err := json.Unmarshal([]byte(ev.Detail), &jobs); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron list could not be parsed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (a *apiServer) handleCreateCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	site, ok := a.resolveCronSite(w, r)
	if !ok {
		return
	}

	var req struct {
		SchedulePreset string `json:"schedule_preset"`
		Schedule       string `json:"schedule"`
		Command        string `json:"command"`
		Label          string `json:"label"`
		Enabled        *bool  `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	schedule, err := resolveCronSchedule(req.SchedulePreset, req.Schedule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Command == "" {
		writeErr(w, http.StatusBadRequest, "command is required")
		return
	}

	params := map[string]any{
		"system_user": site.SystemUser,
		"schedule":    schedule,
		"command":     req.Command,
		"label":       req.Label,
	}
	if req.Enabled != nil {
		params["enabled"] = *req.Enabled
	}

	ctx, cancel := context.WithTimeout(r.Context(), cronDispatchTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, site.ServerID, actor, capabilities.CapCronCreate, params)
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.create failed on the agent: "+ev.Message)
		return
	}

	var job cronJob
	if err := json.Unmarshal([]byte(ev.Detail), &job); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron entry was created on the agent but its result could not be parsed: "+err.Error())
		return
	}
	a.store.log(site.ServerID, actor, "cron.created", fmt.Sprintf("site_id=%s id=%s schedule=%q command=%q", site.ID, job.ID, job.Schedule, job.Command))
	writeJSON(w, http.StatusCreated, job)
}

func (a *apiServer) handleUpdateCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	site, ok := a.resolveCronSite(w, r)
	if !ok {
		return
	}
	cronID := r.PathValue("cronId")

	var req struct {
		SchedulePreset string `json:"schedule_preset"`
		Schedule       string `json:"schedule"`
		Command        string `json:"command"`
		Label          string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	schedule, err := resolveCronSchedule(req.SchedulePreset, req.Schedule)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Command == "" {
		writeErr(w, http.StatusBadRequest, "command is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), cronDispatchTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, site.ServerID, actor, capabilities.CapCronUpdate, map[string]any{
		"system_user": site.SystemUser, "id": cronID, "schedule": schedule, "command": req.Command, "label": req.Label,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.update failed on the agent: "+ev.Message)
		return
	}

	var job cronJob
	if err := json.Unmarshal([]byte(ev.Detail), &job); err != nil {
		writeErr(w, http.StatusInternalServerError, "cron entry was updated on the agent but its result could not be parsed: "+err.Error())
		return
	}
	a.store.log(site.ServerID, actor, "cron.updated", fmt.Sprintf("site_id=%s id=%s schedule=%q command=%q", site.ID, cronID, schedule, req.Command))
	writeJSON(w, http.StatusOK, job)
}

func (a *apiServer) handleDeleteCron(w http.ResponseWriter, r *http.Request) {
	actor := sessionFromContext(r.Context()).Email
	site, ok := a.resolveCronSite(w, r)
	if !ok {
		return
	}
	cronID := r.PathValue("cronId")

	ctx, cancel := context.WithTimeout(r.Context(), cronDispatchTimeout)
	defer cancel()

	ev, err := a.gw.dispatch(ctx, site.ServerID, actor, capabilities.CapCronDelete, map[string]any{
		"system_user": site.SystemUser, "id": cronID,
	})
	if err != nil {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	if ev.Status != proto.TaskSucceeded {
		writeErr(w, http.StatusUnprocessableEntity, "cron.delete failed on the agent: "+ev.Message)
		return
	}

	a.store.log(site.ServerID, actor, "cron.deleted", fmt.Sprintf("site_id=%s id=%s", site.ID, cronID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleSetCronEnabled returns a handler bound to a fixed target state
// (true for the /enable route, false for /disable), rather than reading
// "enabled" from the request body — makes the two routes' method+path
// self-explanatory and impossible to invoke with a body/URL mismatch.
func (a *apiServer) handleSetCronEnabled(enabled bool) http.HandlerFunc {
	action := "cron.disabled"
	if enabled {
		action = "cron.enabled"
	}
	return func(w http.ResponseWriter, r *http.Request) {
		actor := sessionFromContext(r.Context()).Email
		site, ok := a.resolveCronSite(w, r)
		if !ok {
			return
		}
		cronID := r.PathValue("cronId")

		ctx, cancel := context.WithTimeout(r.Context(), cronDispatchTimeout)
		defer cancel()

		ev, err := a.gw.dispatch(ctx, site.ServerID, actor, capabilities.CapCronSetEnabled, map[string]any{
			"system_user": site.SystemUser, "id": cronID, "enabled": enabled,
		})
		if err != nil {
			writeErr(w, http.StatusBadGateway, err.Error())
			return
		}
		if ev.Status != proto.TaskSucceeded {
			writeErr(w, http.StatusUnprocessableEntity, "cron.set_enabled failed on the agent: "+ev.Message)
			return
		}

		var job cronJob
		if err := json.Unmarshal([]byte(ev.Detail), &job); err != nil {
			writeErr(w, http.StatusInternalServerError, "cron entry state was changed on the agent but its result could not be parsed: "+err.Error())
			return
		}
		a.store.log(site.ServerID, actor, action, fmt.Sprintf("site_id=%s id=%s", site.ID, cronID))
		writeJSON(w, http.StatusOK, job)
	}
}
