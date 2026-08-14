package main

import (
	"embed"
	"net/http"
	"os"
)

//go:embed web/index.html
var embeddedWeb embed.FS

// mountDashboard serves the browser dashboard. It's a single self-contained
// static HTML page (no build step, no frontend framework) embedded into the
// binary at compile time, so the control plane is one deployable artifact
// with no separate frontend asset pipeline to keep in sync. -public-dir can
// override this with an on-disk file for local frontend iteration without
// recompiling. Every non-API GET serves the same page (there's only one —
// client-side JS handles view switching), so whatever path a browser was
// pointed at still lands on a working dashboard.
func (a *apiServer) mountDashboard(mux *http.ServeMux) {
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		var page []byte
		if a.publicDir != "" {
			data, err := os.ReadFile(a.publicDir + "/index.html")
			if err != nil {
				http.Error(w, "dashboard asset not found", http.StatusInternalServerError)
				return
			}
			page = data
		} else {
			data, err := embeddedWeb.ReadFile("web/index.html")
			if err != nil {
				http.Error(w, "dashboard asset not found", http.StatusInternalServerError)
				return
			}
			page = data
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(page)
	})
}
