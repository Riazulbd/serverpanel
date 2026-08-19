package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

//go:embed release/install.sh release/serverpanel-agent.service
var embeddedRelease embed.FS

// downloadNameRe is the allow-list for what mountDownloads will ever read
// off disk and serve — this is a public, unauthenticated endpoint (an
// agent has no credentials yet when it fetches its own binary), so it must
// never resolve to anything beyond a literal filename in agentBinariesDir.
var downloadNameRe = regexp.MustCompile(`^serverpanel-agent-linux-(amd64|arm64)(\.sha256)?$`)

// mountDownloads serves everything install.sh needs to fetch, from this
// same control plane: the install script itself, the systemd unit, and
// the agent binary for the requesting host's architecture. This is what
// makes the one-line install command self-contained — there is no
// separate release host to stand up or keep in sync (see
// docs/implementation-status.md, "installable now?").
//
// Binaries are cross-compiled ahead of time by scripts/build-agent-releases.sh
// into agentBinariesDir (default ./dist) — the control plane serves
// whatever's there rather than building anything itself, so a production
// deployment doesn't need a Go toolchain or the source tree present.
func (a *apiServer) mountDownloads(mux *http.ServeMux) {
	mux.HandleFunc("GET /install.sh", func(w http.ResponseWriter, r *http.Request) {
		data, err := embeddedRelease.ReadFile("release/install.sh")
		if err != nil {
			http.Error(w, "install.sh not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Write(data)
	})

	mux.HandleFunc("GET /downloads/serverpanel-agent.service", func(w http.ResponseWriter, r *http.Request) {
		data, err := embeddedRelease.ReadFile("release/serverpanel-agent.service")
		if err != nil {
			http.Error(w, "unit file not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	})

	mux.HandleFunc("GET /downloads/{file}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("file")
		if !downloadNameRe.MatchString(name) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		path := filepath.Join(a.agentBinariesDir, name)

		if len(name) > 7 && name[len(name)-7:] == ".sha256" {
			binPath := path[:len(path)-len(".sha256")]
			sum, err := sha256File(binPath)
			if err != nil {
				http.Error(w, "agent binary not built for this architecture yet — run scripts/build-agent-releases.sh", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "%s\n", sum)
			return
		}

		f, err := os.Open(path)
		if err != nil {
			http.Error(w, "agent binary not built for this architecture yet — run scripts/build-agent-releases.sh", http.StatusNotFound)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		io.Copy(w, f)
	})
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
