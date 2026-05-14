package handler

import (
	"bufio"
	"encoding/json"
	"github.com/google/uuid"
	"io"
	"net/http"
	"network-monitor-backend/internal/domain"
	"network-monitor-backend/internal/httpx"
	"network-monitor-backend/internal/middleware"
	"network-monitor-backend/internal/pkg/hash"
	"network-monitor-backend/internal/repository/postgres"
	"network-monitor-backend/internal/service"
	"strings"
)

type AgentHandler struct {
	agents *postgres.AgentRepo
	ingest *service.LogIngestService
}

func NewAgentHandler(agents *postgres.AgentRepo, ingest *service.LogIngestService) *AgentHandler {
	return &AgentHandler{agents: agents, ingest: ingest}
}
func (h *AgentHandler) CreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AgentName string `json:"agent_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.AgentName) == "" {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "agent_name is required", nil)
		return
	}
	token := hash.NewAgentToken()
	prefix := token
	if len(prefix) > 8 {
		prefix = prefix[:8] + "..."
	}
	a, err := h.agents.Create(r.Context(), req.AgentName, hash.SHA256(token), prefix)
	if err != nil {
		httpx.Error(w, 500, "AGENT_CREATE_FAILED", err.Error(), nil)
		return
	}
	httpx.JSON(w, 201, map[string]any{"agent_id": a.ID, "token": token, "created_at": a.CreatedAt})
}
func (h *AgentHandler) List(w http.ResponseWriter, r *http.Request) {
	items, err := h.agents.List(r.Context())
	if err != nil {
		httpx.Error(w, 500, "AGENTS_QUERY_FAILED", err.Error(), nil)
		return
	}
	httpx.JSON(w, 200, map[string]any{"items": items})
}
func (h *AgentHandler) UploadLogs(w http.ResponseWriter, r *http.Request) {
	ag, ok := r.Context().Value(middleware.AgentKey).(*domain.Agent)
	if !ok {
		httpx.Error(w, 401, "INVALID_TOKEN", "Agent token is invalid or revoked", nil)
		return
	}
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "multipart form is invalid", nil)
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "file field is required (send a .jsonl file)", nil)
		return
	}
	defer file.Close()

	var valid []domain.NetworkLog
	var invalid []domain.ValidationError
	idx := 0

	scanner := bufio.NewScanner(io.LimitReader(file, 55<<20))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // строки до 1MB
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		log, err := domain.ParseNetworkLog([]byte(line), ag.ID)
		if err != nil {
			invalid = append(invalid, domain.ValidationError{Index: idx, Reason: err.Error()})
			idx++
			continue
		}
		valid = append(valid, log)
		idx++
	}

	if len(valid) == 0 {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "JSONL file contains no valid log entries", nil)
		return
	}

	go h.ingest.ProcessBatch(valid, ag.ID)
	httpx.JSON(w, http.StatusAccepted, map[string]any{"batch_id": uuid.New(), "records_received": len(valid) + len(invalid), "records_valid": len(valid), "records_invalid": len(invalid), "processing_status": "queued"})
}
