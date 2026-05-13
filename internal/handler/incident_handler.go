package handler

import (
	"encoding/json"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"math"
	"net/http"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/middleware"
	jwtutil "network-monitor-backend/internal/pkg/jwt"
	"network-monitor-backend/internal/repository/postgres"
	"strconv"
)

type IncidentHandler struct{ incidents *postgres.IncidentRepo }

func NewIncidentHandler(incidents *postgres.IncidentRepo) *IncidentHandler {
	return &IncidentHandler{incidents: incidents}
}
func (h *IncidentHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := postgres.IncidentFilters{Page: atoi(q.Get("page"), 1), Limit: atoi(q.Get("limit"), 50), Status: q.Get("status"), ThreatType: q.Get("threat_type"), AgentID: q.Get("agent_id"), From: q.Get("from"), To: q.Get("to"), SortBy: q.Get("sort_by"), Order: q.Get("order"), SeverityMin: atoi(q.Get("severity_min"), 0), SeverityMax: atoi(q.Get("severity_max"), 0)}
	items, total, err := h.incidents.List(r.Context(), f)
	if err != nil {
		httpx.Error(w, 500, "INCIDENTS_QUERY_FAILED", err.Error(), nil)
		return
	}
	totalPages := int(math.Ceil(float64(total) / float64(f.Limit)))
	httpx.JSON(w, 200, map[string]any{"items": items, "pagination": map[string]any{"page": f.Page, "limit": f.Limit, "total": total, "total_pages": totalPages}})
}
func (h *IncidentHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		httpx.Error(w, 400, "INVALID_ID", "Invalid incident id", nil)
		return
	}
	inc, err := h.incidents.Get(r.Context(), id)
	if err != nil {
		httpx.Error(w, 500, "INCIDENT_QUERY_FAILED", err.Error(), nil)
		return
	}
	if inc == nil {
		httpx.Error(w, 404, "NOT_FOUND", "Incident not found", nil)
		return
	}
	httpx.JSON(w, 200, map[string]any{"id": inc.ID, "agent_id": inc.AgentID, "agent_name": inc.AgentName, "created_at": inc.CreatedAt, "threat_type": inc.ThreatType, "severity": inc.Severity, "status": inc.Status, "ml_score": inc.MLScore, "details": inc.Details, "raw_logs_sample": []any{}, "timeline": []map[string]any{{"timestamp": inc.CreatedAt, "event": "incident_created"}}})
}
func (h *IncidentHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(mux.Vars(r)["id"])
	if err != nil {
		httpx.Error(w, 400, "INVALID_ID", "Invalid incident id", nil)
		return
	}
	var req struct {
		Status  string `json:"status"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httpx.Error(w, 400, "INVALID_JSON", "Invalid JSON body", nil)
		return
	}
	allowed := map[string]bool{"new": true, "investigating": true, "resolved": true, "false_positive": true}
	if !allowed[req.Status] {
		httpx.Error(w, 400, "INVALID_STATUS", "Status is not allowed", nil)
		return
	}
	claims, _ := r.Context().Value(middleware.UserKey).(*jwtutil.Claims)
	userID := uuid.Nil
	login := "system"
	if claims != nil {
		userID = claims.UserID
		login = claims.Login
	}
	if err := h.incidents.UpdateStatus(r.Context(), id, userID, req.Status); err != nil {
		httpx.Error(w, 500, "STATUS_UPDATE_FAILED", err.Error(), nil)
		return
	}
	httpx.JSON(w, 200, map[string]any{"id": id, "status": req.Status, "updated_by": login})
}
func atoi(v string, d int) int {
	if v == "" {
		return d
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return d
	}
	return n
}
