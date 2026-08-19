package capabilities

import (
	"context"
	"strings"
	"testing"
)

// TestRegistryIsExactlyTheReviewedSet pins the capability list. Adding a
// capability is supposed to be a deliberate, reviewed code change (see the
// package doc); this test makes an accidental or quietly-introduced
// addition fail CI rather than ship. If you're here because you added a
// capability on purpose, add it to this list too — after checking it
// validates its own params and never takes a free-form command string.
func TestRegistryIsExactlyTheReviewedSet(t *testing.T) {
	want := map[string]bool{
		"system.ping": true, "service.control": true, "diagnostics.basic": true,
		"stack.install": true, "site.create": true, "site.set_php_version": true,
		"site.set_status": true, "app.wordpress_install": true,
		"ssl.issue_letsencrypt": true, "ssl.install_custom": true,
		"db.create": true, "db.delete": true, "db.list": true,
		"file.list": true, "file.read": true, "file.write": true, "file.delete": true,
		"backup.run": true, "logs.tail": true,
	}

	got := Default()
	for name := range got {
		if !want[name] {
			t.Errorf("unreviewed capability %q is registered; every capability must be deliberately reviewed", name)
		}
	}
	for name := range want {
		if _, ok := got[name]; !ok {
			t.Errorf("expected capability %q is missing from the registry", name)
		}
	}
}

// TestNoArbitraryExecutionCapability is the automated form of the product's
// hardest constraint: the agent must not offer arbitrary shell-command
// execution. A capability named anything like exec/shell/run/command is
// the most likely shape that violation would take.
func TestNoArbitraryExecutionCapability(t *testing.T) {
	forbidden := []string{"exec", "shell", "command", "cmd", "eval", "script", "sudo"}
	for name := range Default() {
		lower := strings.ToLower(name)
		for _, bad := range forbidden {
			if strings.Contains(lower, bad) {
				t.Errorf("capability %q looks like an arbitrary-execution entry point (matched %q)", name, bad)
			}
		}
	}
}

func TestDispatchRejectsUnknownCapability(t *testing.T) {
	reg := Default()
	for _, name := range []string{"", "shell.exec", "system.Ping", "../system.ping", "db.drop_everything"} {
		if _, err := reg.Dispatch(context.Background(), name, nil, nil); err == nil {
			t.Errorf("Dispatch(%q) succeeded; unknown capabilities must be rejected", name)
		}
	}
}

// TestDispatchToleratesNilProgress guards the nil-progress fallback in
// Dispatch — a handler calling progress() must never panic just because
// the caller didn't supply one.
func TestDispatchToleratesNilProgress(t *testing.T) {
	reg := Default()
	if _, err := reg.Dispatch(context.Background(), CapSystemPing, map[string]any{}, nil); err != nil {
		t.Fatalf("system.ping with nil progress: %v", err)
	}
}

func TestServiceControlRejectsUnmanagedUnits(t *testing.T) {
	// sshd is the important case: stopping it is exactly the kind of
	// lockout the allow-list exists to prevent.
	for _, unit := range []string{"ssh", "sshd", "systemd-journald", "nginx; rm -rf /", "", "../../nginx"} {
		_, err := handleServiceControl(context.Background(),
			map[string]any{"unit": unit, "action": "stop"}, func(string) {})
		if err == nil {
			t.Errorf("service.control accepted unmanaged unit %q", unit)
		}
	}
}

func TestServiceControlRejectsUnknownActions(t *testing.T) {
	for _, action := range []string{"mask", "disable", "edit", "", "restart; reboot"} {
		_, err := handleServiceControl(context.Background(),
			map[string]any{"unit": "nginx", "action": action}, func(string) {})
		if err == nil {
			t.Errorf("service.control accepted non-allow-listed action %q", action)
		}
	}
}

// TestServiceControlRejectsWrongParamTypes covers the map[string]any
// unpacking: a non-string param must fail validation rather than silently
// become the zero value and take some other path.
func TestServiceControlRejectsWrongParamTypes(t *testing.T) {
	_, err := handleServiceControl(context.Background(),
		map[string]any{"unit": 42, "action": []string{"stop"}}, func(string) {})
	if err == nil {
		t.Error("service.control accepted non-string params")
	}
}

func TestStackInstallRejectsUnknownProfile(t *testing.T) {
	for _, profile := range []string{"", "phase2", "phase1-lemp-extra", "PHASE1-LEMP"} {
		_, err := handleStackInstall(context.Background(),
			map[string]any{"profile": profile}, func(string) {})
		if err == nil {
			t.Errorf("stack.install accepted unknown profile %q", profile)
		}
	}
}
