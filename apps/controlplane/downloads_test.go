package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newDownloadAPI(t *testing.T) *apiServer {
	t.Helper()
	api := newTestAPI(t)
	api.agentBinariesDir = t.TempDir()
	return api
}

// TestDownloadsRejectPathTraversal is the important one: /downloads/ is
// unauthenticated by necessity (a VPS has no credentials before it
// registers), so the filename must never be able to escape the binaries
// directory.
func TestDownloadsRejectPathTraversal(t *testing.T) {
	api := newDownloadAPI(t)
	h := api.routes()

	// Write a file outside the served directory that a traversal would target.
	secret := filepath.Join(filepath.Dir(api.agentBinariesDir), "secret.txt")
	if err := os.WriteFile(secret, []byte("do not serve me"), 0600); err != nil {
		t.Fatalf("write bait file: %v", err)
	}

	for _, name := range []string{
		"../secret.txt",
		"..%2Fsecret.txt",
		"....//secret.txt",
		"/etc/passwd",
		"serverpanel-agent-linux-amd64/../../secret.txt",
		"serverpanel-agent-linux-mips",
		"agent-ca-key.pem",
		"",
	} {
		r := httptest.NewRequest("GET", "/downloads/"+name, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)

		if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "do not serve me") {
			t.Errorf("/downloads/%s served a file outside the binaries directory", name)
		}
		if w.Code == http.StatusOK && name != "" {
			t.Errorf("/downloads/%s unexpectedly returned 200", name)
		}
	}
}

func TestDownloadsServeBinaryAndMatchingChecksum(t *testing.T) {
	api := newDownloadAPI(t)
	h := api.routes()

	content := []byte("\x7fELF pretend agent binary")
	binPath := filepath.Join(api.agentBinariesDir, "serverpanel-agent-linux-amd64")
	if err := os.WriteFile(binPath, content, 0755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/downloads/serverpanel-agent-linux-amd64", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("binary download = %d, want 200", w.Code)
	}
	if w.Body.String() != string(content) {
		t.Error("served binary content does not match the file on disk")
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/downloads/serverpanel-agent-linux-amd64.sha256", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("checksum download = %d, want 200", w.Code)
	}
	sum := sha256.Sum256(content)
	if got := strings.TrimSpace(w.Body.String()); got != hex.EncodeToString(sum[:]) {
		t.Errorf("served checksum %q does not match the binary's actual SHA-256 %s — install.sh would reject a good binary",
			got, hex.EncodeToString(sum[:]))
	}
}

func TestDownloadsReportMissingBinaryClearly(t *testing.T) {
	api := newDownloadAPI(t)
	h := api.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/downloads/serverpanel-agent-linux-arm64", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("missing binary = %d, want 404", w.Code)
	}
	if !strings.Contains(w.Body.String(), "build-agent-releases") {
		t.Errorf("404 body should point at the build script, got: %s", w.Body.String())
	}
}

// TestInstallScriptIsServedAndSelfConsistent guards against the installer
// drifting away from the endpoints that actually exist.
func TestInstallScriptIsServedAndSelfConsistent(t *testing.T) {
	api := newDownloadAPI(t)
	h := api.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/install.sh", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("/install.sh = %d, want 200", w.Code)
	}
	script := w.Body.String()

	if !strings.HasPrefix(script, "#!") {
		t.Error("/install.sh does not start with a shebang")
	}
	// The script must not reference the placeholder hosts that made the
	// original install flow non-functional.
	if strings.Contains(script, "serverpanel.example") {
		t.Error("/install.sh still references a placeholder host")
	}
	// It must fetch the arch-suffixed names this server actually serves.
	for _, want := range []string{"serverpanel-agent-linux-", "--register-only", "sha256sum"} {
		if !strings.Contains(script, want) {
			t.Errorf("/install.sh missing expected content %q", want)
		}
	}
	// The GOARCH names the download handler accepts must be the ones the
	// script maps uname output onto.
	for _, arch := range []string{"amd64", "arm64"} {
		if !strings.Contains(script, arch) {
			t.Errorf("/install.sh does not handle architecture %q", arch)
		}
	}
}

func TestSystemdUnitIsServed(t *testing.T) {
	api := newDownloadAPI(t)
	h := api.routes()

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/downloads/serverpanel-agent.service", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("unit file = %d, want 200", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{"[Unit]", "[Service]", "ExecStart=", "[Install]"} {
		if !strings.Contains(body, want) {
			t.Errorf("served systemd unit missing %q", want)
		}
	}
	// The long-running unit must not carry a bootstrap token.
	if strings.Contains(body, "--token") {
		t.Error("systemd unit contains a --token argument; the bootstrap secret must not persist in the unit file")
	}
}

// TestDownloadsDoNotRequireAuth documents intent: these endpoints are
// deliberately public because a VPS has no credentials until it
// registers. If that ever changes, this test should change with it.
func TestDownloadsDoNotRequireAuth(t *testing.T) {
	api := newDownloadAPI(t)
	h := api.routes()

	for _, path := range []string{"/install.sh", "/downloads/serverpanel-agent.service"} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code == http.StatusUnauthorized {
			t.Errorf("%s requires auth, but an unregistered VPS has no credentials to present", path)
		}
	}
}
