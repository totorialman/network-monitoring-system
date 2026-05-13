package handler

import (
	"context"
	"net/http"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/repository/postgres"
)

type LogCounter interface{ Count(context.Context) int64 }
type StatsHandler struct {
	incidents *postgres.IncidentRepo
	logs      LogCounter
}

func NewStatsHandler(incidents *postgres.IncidentRepo, logs LogCounter) *StatsHandler {
	return &StatsHandler{incidents: incidents, logs: logs}
}
func (h *StatsHandler) Stats(w http.ResponseWriter, r *http.Request) {
	st, err := h.incidents.Stats(r.Context())
	if err != nil {
		httpx.Error(w, 500, "STATS_FAILED", err.Error(), nil)
		return
	}
	overview := map[string]any{"total_incidents": st["total_incidents"], "new_incidents": st["new_incidents"], "active_agents": st["active_agents"], "total_logs_processed": h.logs.Count(r.Context()), "avg_ml_score": st["avg_ml_score"]}
	httpx.JSON(w, 200, map[string]any{"overview": overview, "timeseries": []any{}, "threat_distribution": st["threat_distribution"], "top_sources": []any{}})
}
