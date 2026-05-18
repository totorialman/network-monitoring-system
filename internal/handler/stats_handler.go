package handler

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/repository/postgres"
)

// LogQuerier расширенный интерфейс для ClickHouse-лог-репозитория:
// Count — для дашборда, RawSample — для «разворачивания» сырых логов инцидента.
type LogQuerier interface {
	Count(context.Context) int64
	CountSince(ctx context.Context, since time.Time) int64
	RawSample(ctx context.Context, agentID string, limit int) []map[string]any
}

type StatsHandler struct {
	incidents *postgres.IncidentRepo
	logs      LogQuerier
}

func NewStatsHandler(incidents *postgres.IncidentRepo, logs LogQuerier) *StatsHandler {
	return &StatsHandler{incidents: incidents, logs: logs}
}
func (h *StatsHandler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	st, err := h.incidents.Stats(ctx, period)
	if err != nil {
		httpx.Error(w, 500, "STATS_FAILED", err.Error(), nil)
		return
	}

	// Получаем timeseries из БД
	timeseries := h.incidents.Timeseries(ctx, period)

	// Получаем top_sources из БД
	topSources := h.incidents.TopSources(ctx, period)

	logCount := h.logs.Count(ctx)
	if period != "" {
		since := periodToTime(period)
		if cnt := h.logs.CountSince(ctx, since); cnt > 0 {
			logCount = cnt
		}
	}
	overview := map[string]any{
		"total_incidents":      st["total_incidents"],
		"new_incidents":        st["new_incidents"],
		"critical_count":       st["critical_count"],
		"active_agents":         st["active_agents"],
		"total_logs_processed":  logCount,
		"avg_ml_score":         st["avg_ml_score"],
	}
	httpx.JSON(w, 200, map[string]any{
		"overview":            overview,
		"timeseries":          timeseries,
		"threat_distribution": st["threat_distribution"],
		"top_sources":         topSources,
	})
}

// AgentLogs возвращает сырые логи из ClickHouse для указанного агента.
// Используется фронтендом при «разворачивании» инцидента:
// GET /api/agents/{agent_id}/logs?limit=100
func (h *StatsHandler) AgentLogs(w http.ResponseWriter, r *http.Request) {
	agentID := mux.Vars(r)["agent_id"]
	if agentID == "" {
		httpx.Error(w, http.StatusBadRequest, "MISSING_AGENT_ID", "agent_id is required", nil)
		return
	}

	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	logs := h.logs.RawSample(r.Context(), agentID, limit)
	httpx.JSON(w, http.StatusOK, map[string]any{
		"logs":  logs,
		"total": len(logs),
	})
}

var _ = strconv.Itoa

func periodToTime(period string) time.Time {
	switch period {
	case "1h":
		return time.Now().Add(-1 * time.Hour)
	case "6h":
		return time.Now().Add(-6 * time.Hour)
	case "24h":
		return time.Now().Add(-24 * time.Hour)
	case "7d":
		return time.Now().Add(-7 * 24 * time.Hour)
	case "30d":
		return time.Now().Add(-30 * 24 * time.Hour)
	default:
		return time.Now().Add(-24 * time.Hour)
	}
}
