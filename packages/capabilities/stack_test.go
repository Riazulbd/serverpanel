package capabilities

import (
	"strings"
	"testing"
)

// TestCertbotDeployHookScriptIsFixedAndSafe locks down the one property that
// matters for a script the agent writes to disk with 0755 and lets certbot
// execute unattended after every renewal: it takes no caller/template input
// (so there is nothing here for a task's params to ever influence) and it
// only ever reloads nginx, never anything broader.
func TestCertbotDeployHookScriptIsFixedAndSafe(t *testing.T) {
	script := certbotDeployHookScript()

	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Fatalf("deploy hook must start with a shebang, got: %q", script)
	}
	if !strings.Contains(script, "systemctl reload nginx") {
		t.Fatalf("deploy hook must reload nginx, got: %q", script)
	}
	if strings.Count(script, "systemctl") != 1 {
		t.Fatalf("deploy hook should invoke systemctl exactly once, got: %q", script)
	}

	// Deterministic: this is what stack.install's idempotency Check compares
	// on-disk content against, so it must not vary between calls.
	if second := certbotDeployHookScript(); script != second {
		t.Fatalf("certbotDeployHookScript() is not deterministic: %q != %q", script, second)
	}
}

func TestCertbotDeployHookPathIsUnderRenewalHooksDeployDir(t *testing.T) {
	if !strings.HasPrefix(certbotDeployHookPath, certbotRenewalHooksDir+"/") {
		t.Fatalf("certbotDeployHookPath = %q, want it under %q (certbot only executes scripts it finds in this exact directory)",
			certbotDeployHookPath, certbotRenewalHooksDir)
	}
}

// TestCertbotTimerIsAManagedUnit ensures the auto-renewal timer wired up by
// stack.install is also visible through diagnostics.basic and controllable
// via the existing service.control allow-list, rather than being a step that
// silently falls outside both.
func TestCertbotTimerIsAManagedUnit(t *testing.T) {
	if !managedUnits["certbot.timer"] {
		t.Fatal(`managedUnits["certbot.timer"] = false, want true — stack.install enables this timer and diagnostics.basic/service.control should cover it`)
	}
}
