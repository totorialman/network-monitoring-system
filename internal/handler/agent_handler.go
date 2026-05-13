package handler

import (
	"archive/zip"
	"bytes"
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
	file, _, err := r.FormFile("archive")
	if err != nil {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "archive field is required", nil)
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 55<<20))
	if err != nil {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "cannot read archive", nil)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "ZIP archive is corrupted", nil)
		return
	}

	// Проверяем, что в архиве есть хотя бы один .json файл
	hasJSON := false
	for _, f := range zr.File {
		if !f.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			hasJSON = true
			break
		}
	}
	if !hasJSON {
		httpx.Error(w, 400, "INVALID_PAYLOAD", "ZIP archive must contain at least one .json file", nil)
		return
	}

	var valid []domain.NetworkLog
	var invalid []domain.ValidationError
	idx := 0

	// Обрабатываем все .json файлы в архиве
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		// Пробуем распарсить как JSON-массив
		var fileLogs []json.RawMessage
		if err := json.Unmarshal(raw, &fileLogs); err != nil {
			// Если не массив — пробуем как одиночный объект
			var single json.RawMessage
			if err2 := json.Unmarshal(raw, &single); err2 != nil {
				invalid = append(invalid, domain.ValidationError{Index: idx, Reason: "json_parse_error"})
				idx++
				continue
			}
			fileLogs = []json.RawMessage{single}
		}

		for _, rawMsg := range fileLogs {
			log, err := domain.ParseNetworkLog(rawMsg, ag.ID)
			if err != nil {
				invalid = append(invalid, domain.ValidationError{Index: idx, Reason: err.Error()})
				idx++
				continue
			}
			valid = append(valid, log)
			idx++
		}
	}

	if len(valid) > 0 {
		go h.ingest.ProcessBatch(valid, ag.ID)
	}
	httpx.JSON(w, http.StatusAccepted, map[string]any{"batch_id": uuid.New(), "records_received": len(valid) + len(invalid), "records_valid": len(valid), "records_invalid": len(invalid), "processing_status": "queued"})
}
