package capabilities

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDispatchRejectsUnknownCapability(t *testing.T) {
	r := Default()
	_, err := r.Dispatch(context.Background(), "shell.exec", nil, nil)
	if err == nil {
		t.Fatal("expected an unknown capability name to be rejected")
	}
	if !strings.Contains(err.Error(), "not in the agent's allow-list") {
		t.Fatalf("error = %q, want it to mention the allow-list", err.Error())
	}
}

func TestDispatchSystemPing(t *testing.T) {
	r := Default()
	out, err := r.Dispatch(context.Background(), CapSystemPing, nil, nil)
	if err != nil {
		t.Fatalf("system.ping: %v", err)
	}
	if !strings.HasPrefix(out, "pong from") {
		t.Fatalf("system.ping output = %q, want it to start with 'pong from'", out)
	}
}

func TestDispatchNilProgressDoesNotPanic(t *testing.T) {
	r := Default()
	if _, err := r.Dispatch(context.Background(), CapSystemPing, nil, nil); err != nil {
		t.Fatalf("system.ping with nil progress: %v", err)
	}
}

func TestServiceControlRejectsNonAllowlistedUnit(t *testing.T) {
	_, err := handleServiceControl(context.Background(), map[string]any{
		"unit": "ssh", "action": "restart",
	}, nil)
	if err == nil {
		t.Fatal("expected a non-allow-listed unit to be rejected")
	}
	if !strings.Contains(err.Error(), "not an allow-listed managed service") {
		t.Fatalf("error = %q, want it to mention the allow-list", err.Error())
	}
}

func TestServiceControlRejectsNonAllowlistedAction(t *testing.T) {
	_, err := handleServiceControl(context.Background(), map[string]any{
		"unit": "nginx", "action": "reload-and-rm-rf",
	}, nil)
	if err == nil {
		t.Fatal("expected a non-allow-listed action to be rejected")
	}
	if !strings.Contains(err.Error(), "not an allow-listed service action") {
		t.Fatalf("error = %q, want it to mention the allow-list", err.Error())
	}
}

// TestServiceControlRejectsInjectionAttempt guards against the classic
// confused-deputy failure mode called out in docs/product-plan.md §8.10: a
// capability parameter crafted to look like a unit name but actually meant
// to smuggle extra arguments into the fixed argv. Since exec.CommandContext
// takes a literal argv (never a shell string), this is defense in depth, but
// the allow-list check must still reject it outright rather than passing it
// through to systemctl.
func TestServiceControlRejectsInjectionAttempt(t *testing.T) {
	_, err := handleServiceControl(context.Background(), map[string]any{
		"unit": "nginx; rm -rf /", "action": "restart",
	}, nil)
	if err == nil {
		t.Fatal("expected a unit name containing shell metacharacters to be rejected")
	}
}

func TestServiceControlRejectsMissingParams(t *testing.T) {
	_, err := handleServiceControl(context.Background(), map[string]any{}, nil)
	if err == nil {
		t.Fatal("expected missing unit/action params to be rejected")
	}
}

func TestDefaultRegistryCoversAllDeclaredCapabilityConstants(t *testing.T) {
	r := Default()
	want := []string{
		CapSystemPing, CapServiceControl, CapDiagnosticsBase, CapStackInstall,
		CapSiteCreate, CapSiteSetPHP, CapSiteSetStatus, CapWordPressInstall,
		CapSSLIssueLE, CapSSLInstallCustom, CapDBCreate, CapDBDelete, CapDBList,
		CapFileList, CapFileRead, CapFileWrite, CapFileDelete, CapBackupRun, CapBackupRestore, CapLogsTail,
	}
	for _, name := range want {
		if _, ok := r[name]; !ok {
			t.Errorf("Default() registry is missing handler for declared capability %q", name)
		}
	}
	if len(r) != len(want) {
		t.Errorf("Default() registry has %d entries, want %d (extra capability not covered by this test?)", len(r), len(want))
	}
}

// installFakeSystemctl puts a fake `systemctl` script at the front of PATH
// that answers `is-enabled`/`is-active certbot.timer` from two env vars,
// mimicking real systemctl's behavior of printing the state word to stdout
// and exiting non-zero whenever that state isn't the "good" one (e.g.
// `is-enabled` on a disabled unit still prints "disabled" but exits 1) —
// which is why certbotTimerStatus (and run()) must read stdout rather than
// rely on the exit code alone.
func installFakeSystemctl(t *testing.T, enabled, active string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake systemctl script requires a POSIX shell")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"case \"$1 $2\" in\n" +
		"  \"is-enabled certbot.timer\") echo \"" + enabled + "\"; [ \"" + enabled + "\" = enabled ] ;;\n" +
		"  \"is-active certbot.timer\") echo \"" + active + "\"; [ \"" + active + "\" = active ] ;;\n" +
		"  *) exit 1 ;;\n" +
		"esac\n"
	path := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestCertbotTimerStatusHealthy(t *testing.T) {
	installFakeSystemctl(t, "enabled", "active")
	got := certbotTimerStatus(context.Background())
	if got != "ok (enabled, active)" {
		t.Fatalf("certbotTimerStatus() = %q, want the healthy message", got)
	}
}

func TestCertbotTimerStatusWarnsWhenNotEnabled(t *testing.T) {
	installFakeSystemctl(t, "disabled", "inactive")
	got := certbotTimerStatus(context.Background())
	if !strings.Contains(got, "WARNING") || !strings.Contains(got, "enabled=disabled") || !strings.Contains(got, "active=inactive") {
		t.Fatalf("certbotTimerStatus() = %q, want a WARNING mentioning both states", got)
	}
}

func TestCertbotTimerStatusWarnsOnPartialState(t *testing.T) {
	// Enabled-but-not-active (e.g. a manual `systemctl stop`) must still
	// warn — a cert can silently stop renewing even though the unit would
	// come back on the next reboot, which "enabled" alone would hide.
	installFakeSystemctl(t, "enabled", "inactive")
	got := certbotTimerStatus(context.Background())
	if !strings.Contains(got, "WARNING") {
		t.Fatalf("certbotTimerStatus() = %q, want a WARNING for enabled-but-inactive", got)
	}
}

func TestDiagnosticsBasicIncludesCertbotTimerWhenCertbotPresent(t *testing.T) {
	// diagnostics.basic only checks the timer when certbot itself is
	// present (os.Stat("/usr/bin/certbot")); this test environment won't
	// have that path, so it only asserts the negative case doesn't panic
	// or otherwise misbehave and never claims a certbot finding that isn't
	// there.
	out, err := handleDiagnosticsBasic(context.Background(), nil, nil)
	if err != nil {
		t.Fatalf("diagnostics.basic: %v", err)
	}
	if _, statErr := os.Stat("/usr/bin/certbot"); statErr != nil && strings.Contains(out, "certbot.timer") {
		t.Fatalf("diagnostics.basic reported a certbot.timer finding without certbot being installed: %q", out)
	}
}
