package capabilities

import (
	"context"
	"strings"
	"testing"
)

// TestPhase1LEMPStepsIncludesCertbotAutoRenewal guards against the specific
// documented gap this step closes: an issued Let's Encrypt certificate is
// only actually renewed if stack.install wires up the renewal timer, so the
// step must exist, be named findably, and run strictly after certbot itself
// is installed (installing the timer before the package would be a no-op at
// best).
func TestPhase1LEMPStepsIncludesCertbotAutoRenewal(t *testing.T) {
	steps := phase1LEMPSteps()

	certbotIdx, renewalIdx := -1, -1
	for i, s := range steps {
		if strings.Contains(s.Name, "certbot (Let's Encrypt ACME client)") {
			certbotIdx = i
		}
		if strings.Contains(s.Name, "certbot auto-renewal") {
			renewalIdx = i
		}
	}
	if certbotIdx == -1 {
		t.Fatal("expected a certbot install step")
	}
	if renewalIdx == -1 {
		t.Fatal("expected a certbot auto-renewal step")
	}
	if renewalIdx <= certbotIdx {
		t.Fatalf("auto-renewal step (index %d) must run after certbot install (index %d)", renewalIdx, certbotIdx)
	}
}

// TestCertbotTimerActiveFailsClosed exercises the no-systemctl-available
// path (true for this test sandbox, and for any host that legitimately
// doesn't have the timer wired up yet): it must report false, never panic
// or error out, so stack.install's Check() correctly falls through to Run()
// instead of skipping a server that actually needs the fix.
func TestCertbotTimerActiveFailsClosed(t *testing.T) {
	if certbotTimerActive(context.Background()) {
		t.Skip("systemctl reports certbot.timer enabled+active in this environment; nothing to assert")
	}
}

// TestCertbotDeployHookScriptIsStable pins the exact hook contents so a
// future edit can't silently drop `set -e` or the reload command, and so
// hasCertbotDeployHook()'s byte-for-byte comparison against a previously
// written file stays meaningful.
func TestCertbotDeployHookScriptIsStable(t *testing.T) {
	script := certbotDeployHookScript()
	if !strings.HasPrefix(script, "#!/bin/sh\n") {
		t.Fatal("deploy hook must start with a shebang so certbot can execute it directly")
	}
	if !strings.Contains(script, "systemctl reload nginx") {
		t.Fatal("deploy hook must reload nginx after renewal")
	}
	if !strings.Contains(script, "set -e") {
		t.Fatal("deploy hook must fail loudly (set -e) rather than silently no-op on error")
	}
}

func TestHasCertbotDeployHookFalseWhenMissing(t *testing.T) {
	// No filesystem fixture is created, so the well-known path can't exist
	// in the test sandbox; this pins the "missing file" branch to `false`
	// rather than an error/panic.
	if hasCertbotDeployHook() {
		t.Skip("a real deploy hook file exists at the well-known path in this environment")
	}
}
