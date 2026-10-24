// Command control-plane runs the Muistamo control plane.
package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"time"

	"muistamo.dev/muistamo/control-plane/internal/health"
)

func main() {
	addr := os.Getenv("CONTROL_PLANE_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health.Handler)

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	slog.Info("control-plane listening", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("control-plane stopped", "err", err)
		os.Exit(1)
	}
}
