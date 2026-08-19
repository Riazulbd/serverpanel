// Package capabilities is the agent's fixed, allow-listed set of actions the
// control plane may request. This is the enforcement point for "the agent
// must not offer arbitrary shell-command execution": there is no handler
// here that takes a free-form command string. Every handler validates its
// own typed parameters and, where it shells out at all, does so with a
// fixed argv built from allow-listed values only — never string
// concatenation of caller-supplied text into a shell.
package capabilities

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Progress reports incremental status for a long-running capability (e.g.
// "installing nginx (3/11)") back to the control plane as it happens,
// rather than only at completion.
type Progress func(message string)

// Handler executes one capability. Params have already been type-asserted
// from the task's raw JSON object by the registry before Handler is called.
type Handler func(ctx context.Context, params map[string]any, progress Progress) (detail string, err error)

// Registry is the fixed capability -> handler map. It is built once at
// startup by Default() and never mutated at runtime by remote input.
type Registry map[string]Handler

// Names of the capabilities Phase 1 ships. Adding a new one is a code
// change + review, not a runtime registration.
const (
	CapSystemPing       = "system.ping"
	CapServiceControl   = "service.control"
	CapDiagnosticsBase  = "diagnostics.basic"
	CapStackInstall     = "stack.install"
	CapSiteCreate       = "site.create"
	CapSiteSetPHP       = "site.set_php_version"
	CapSiteSetStatus    = "site.set_status"
	CapWordPressInstall = "app.wordpress_install"
	CapSSLIssueLE       = "ssl.issue_letsencrypt"
	CapSSLInstallCustom = "ssl.install_custom"
	CapDBCreate         = "db.create"
	CapDBDelete         = "db.delete"
	CapDBList           = "db.list"
	CapFileList         = "file.list"
	CapFileRead         = "file.read"
	CapFileWrite        = "file.write"
	CapFileDelete       = "file.delete"
	CapBackupRun        = "backup.run"
	CapBackupRestore    = "backup.restore"
	CapLogsTail         = "logs.tail"
	CapCronList         = "cron.list"
	CapCronSet          = "cron.set"
	CapCronDelete       = "cron.delete"
)

// managedUnits is the allow-list of systemd units the agent will ever act
// on via service.control. An arbitrary unit name in a task's params is
// rejected, not passed through to systemctl.
var managedUnits = map[string]bool{
	"nginx":        true,
	"php8.3-fpm":   true,
	"mariadb":      true,
	"redis-server": true,
	"cron":         true,
	"fail2ban":     true,
}

// serviceActions is the allow-list of actions service.control accepts.
var serviceActions = map[string]bool{
	"start":   true,
	"stop":    true,
	"restart": true,
	"status":  true,
}

// Default returns the Phase 1 capability registry.
func Default() Registry {
	return Registry{
		CapSystemPing:       handleSystemPing,
		CapServiceControl:   handleServiceControl,
		CapDiagnosticsBase:  handleDiagnosticsBasic,
		CapStackInstall:     handleStackInstall,
		CapSiteCreate:       handleSiteCreate,
		CapSiteSetPHP:       handleSiteSetPHP,
		CapSiteSetStatus:    handleSiteSetStatus,
		CapWordPressInstall: handleWordPressInstall,
		CapSSLIssueLE:       handleSSLIssueLetsEncrypt,
		CapSSLInstallCustom: handleSSLInstallCustom,
		CapDBCreate:         handleDBCreate,
		CapDBDelete:         handleDBDelete,
		CapDBList:           handleDBList,
		CapFileList:         handleFileList,
		CapFileRead:         handleFileRead,
		CapFileWrite:        handleFileWrite,
		CapFileDelete:       handleFileDelete,
		CapBackupRun:        handleBackupRun,
		CapBackupRestore:    handleBackupRestore,
		CapLogsTail:         handleLogsTail,
		CapCronList:         handleCronList,
		CapCronSet:          handleCronSet,
		CapCronDelete:       handleCronDelete,
	}
}

// Dispatch validates that name is a known capability and runs it. It never
// falls through to a generic executor for unknown names.
func (r Registry) Dispatch(ctx context.Context, name string, params map[string]any, progress Progress) (string, error) {
	h, ok := r[name]
	if !ok {
		return "", fmt.Errorf("capability %q is not in the agent's allow-list", name)
	}
	if progress == nil {
		progress = func(string) {}
	}
	return h(ctx, params, progress)
}

func handleSystemPing(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("pong from %s at %s", hostname, time.Now().UTC().Format(time.RFC3339)), nil
}

func handleServiceControl(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	unit, _ := params["unit"].(string)
	action, _ := params["action"].(string)

	if !managedUnits[unit] {
		return "", fmt.Errorf("unit %q is not an allow-listed managed service", unit)
	}
	if !serviceActions[action] {
		return "", fmt.Errorf("action %q is not an allow-listed service action", action)
	}

	// Fixed argv: no shell, no string interpolation of caller-supplied text
	// beyond the two values just validated against allow-lists above.
	cmd := exec.CommandContext(ctx, "systemctl", action, unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("systemctl %s %s: %w: %s", action, unit, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func handleDiagnosticsBasic(ctx context.Context, params map[string]any, progress Progress) (string, error) {
	var findings []string

	for unit := range managedUnits {
		cmd := exec.CommandContext(ctx, "systemctl", "is-active", unit)
		out, _ := cmd.CombinedOutput()
		findings = append(findings, fmt.Sprintf("%s: %s", unit, strings.TrimSpace(string(out))))
	}

	if len(findings) == 0 {
		return "no managed services found to check", nil
	}
	return strings.Join(findings, "; "), nil
}
