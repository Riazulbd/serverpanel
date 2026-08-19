package capabilities

import (
	"context"
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
		CapSSLIssueLE, CapSSLInstallCustom, CapSSLRenewalStatus, CapDBCreate, CapDBDelete, CapDBList,
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
