package handler

import (
	"context"
	"database/sql"
	"net/http"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/service"
	"time"
)

type HealthHandler struct {
	pg      *sql.DB
	ch      interface{ Ping(context.Context) error }
	ml      service.MLClient
	started time.Time
	version string
}

func NewHealthHandler(pg *sql.DB, ch interface{ Ping(context.Context) error }, ml service.MLClient, version string) *HealthHandler {
	return &HealthHandler{pg: pg, ch: ch, ml: ml, started: time.Now(), version: version}
}
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	services := map[string]string{"postgres": "connected", "clickhouse": "connected", "ml_service": "healthy", "telegram": "ok"}
	if err := h.pg.PingContext(ctx); err != nil {
		services["postgres"] = "error"
	}
	if err := h.ch.Ping(ctx); err != nil {
		services["clickhouse"] = "error"
	}
	if err := h.ml.HealthCheck(ctx); err != nil {
		services["ml_service"] = "unhealthy"
	}
	httpx.RawJSON(w, 200, map[string]any{"status": "ok", "services": services, "version": h.version, "uptime_sec": int(time.Since(h.started).Seconds())})
}
