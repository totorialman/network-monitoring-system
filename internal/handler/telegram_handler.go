package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"network-monitor-backend/internal/config"
	"network-monitor-backend/internal/repository/postgres"
)

// TelegramHandler принимает webhook-запросы от Telegram Bot API.
type TelegramHandler struct {
	incidents *postgres.IncidentRepo
	cfg       config.TelegramConfig
	logger    *zap.Logger
	client    *http.Client
	wsHub     *WsHub
}

func NewTelegramHandler(incidents *postgres.IncidentRepo, cfg config.TelegramConfig, logger *zap.Logger, wsHub *WsHub) *TelegramHandler {
	return &TelegramHandler{
		incidents: incidents,
		cfg:       cfg,
		logger:    logger,
		client:    &http.Client{},
		wsHub:     wsHub,
	}
}

// Webhook — эндпоинт для приёма обновлений от Telegram.
// Проверяет secret_token в заголовке X-Telegram-Bot-Api-Secret-Token.
func (h *TelegramHandler) Webhook(w http.ResponseWriter, r *http.Request) {
	secretToken := r.Header.Get("X-Telegram-Bot-Api-Secret-Token")
	if h.cfg.WebhookSecret != "" && secretToken != h.cfg.WebhookSecret {
		h.logger.Warn("telegram webhook: invalid secret token")
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var update struct {
		UpdateID      int            `json:"update_id"`
		CallbackQuery *callbackQuery `json:"callback_query"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		h.logger.Warn("telegram webhook: failed to decode update", zap.Error(err))
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	if update.CallbackQuery != nil {
		go h.handleCallback(update.CallbackQuery)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"ok":true}`))
}

type callbackQuery struct {
	ID      string `json:"id"`
	From    struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	} `json:"from"`
	Message struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
	Data string `json:"data"`
}

// handleCallback обрабатывает нажатие inline-кнопки в Telegram.
// Формат callback_data: "action:incident_uuid"
// Например: "investigating:550e8400-e29b-41d4-a716-446655440000"
func (h *TelegramHandler) handleCallback(cb *callbackQuery) {
	parts := strings.SplitN(cb.Data, ":", 2)
	if len(parts) != 2 {
		h.answerCallback(cb.ID, "Некорректный формат данных", false)
		return
	}

	action := parts[0]
	incidentIDStr := parts[1]

	incidentID, err := uuid.Parse(incidentIDStr)
	if err != nil {
		h.answerCallback(cb.ID, "Некорректный ID инцидента", false)
		return
	}

	statusMap := map[string]string{
		"investigating": "investigating",
		"resolved":      "resolved",
		"false_positive": "false_positive",
	}

	status, ok := statusMap[action]
	if !ok {
		h.answerCallback(cb.ID, "Неизвестное действие: "+action, false)
		return
	}

	// Обновляем статус (uuid.Nil = система)
	if err := h.incidents.UpdateStatus(context.Background(), incidentID, uuid.Nil, status); err != nil {
		h.logger.Error("telegram: failed to update incident status",
			zap.String("incident_id", incidentID.String()),
			zap.String("action", action),
			zap.Error(err),
		)
		h.answerCallback(cb.ID, "❌ Ошибка при обновлении статуса. Попробуйте позже.", false)
		return
	}

	statusLabels := map[string]string{
		"investigating": "🟡 В работе",
		"resolved":      "🟢 Решено",
		"false_positive": "⚪ Ложное срабатывание",
	}
	label := statusLabels[status]

	userName := cb.From.Username
	if userName == "" {
		userName = fmt.Sprintf("ID %d", cb.From.ID)
	}

	text := fmt.Sprintf("✅ Статус инцидента %s изменён на «%s» пользователем @%s",
		incidentID.String()[:8]+"...", label, userName)
	h.answerCallback(cb.ID, text, true)
	h.logger.Info("telegram: incident status updated via bot",
		zap.String("incident_id", incidentID.String()),
		zap.String("status", status),
		zap.String("user", userName),
	)

	// Оповещаем фронтенд через WebSocket
	if h.wsHub != nil {
		h.wsHub.Broadcast(map[string]any{
			"type":    "incident_updated",
			"payload": map[string]any{"incident_id": incidentID.String(), "status": status},
		})
	}
}

// answerCallback отправляет ответ на callback_query (всплывающее уведомление).
func (h *TelegramHandler) answerCallback(callbackID, text string, showAlert bool) {
	url := fmt.Sprintf("https://api.telegram.org/bot%s/answerCallbackQuery", h.cfg.BotToken)
	payload := map[string]any{
		"callback_query_id": callbackID,
		"text":              text,
		"show_alert":        showAlert,
	}
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		h.logger.Warn("telegram: answerCallbackQuery failed", zap.Error(err))
		return
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}
}

// RegisterWebhook регистрирует webhook URL в Telegram Bot API.
func RegisterWebhook(cfg config.TelegramConfig, logger *zap.Logger) {
	if cfg.BotToken == "" {
		logger.Info("telegram: bot token not set, skipping webhook registration")
		return
	}

	webhookURL := strings.TrimSuffix(cfg.BaseIncidentURL, "/incidents") + "/api/telegram/webhook"

	url := fmt.Sprintf("https://api.telegram.org/bot%s/setWebhook", cfg.BotToken)
	payload := map[string]any{
		"url":          webhookURL,
		"secret_token": cfg.WebhookSecret,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		logger.Error("telegram: setWebhook request failed", zap.Error(err), zap.String("webhook_url", webhookURL))
		return
	}
	if resp != nil && resp.Body != nil {
		resp.Body.Close()
	}

	if resp.StatusCode >= 300 {
		logger.Error("telegram: setWebhook returned non-OK status",
			zap.Int("status", resp.StatusCode),
			zap.String("webhook_url", webhookURL))
	} else {
		logger.Info("telegram: webhook registered successfully", zap.String("webhook_url", webhookURL))
	}
}