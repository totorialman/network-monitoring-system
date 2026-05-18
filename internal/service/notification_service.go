package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"net/http"
	"network-monitor-backend/internal/config"
	"network-monitor-backend/internal/domain"
	"time"
)

type AlertRepository interface {
	RecordSent(context.Context, uuid.UUID, string, string)
	RecordFailed(context.Context, uuid.UUID, string, string)
}
type NotificationService struct {
	cfg    config.TelegramConfig
	alerts AlertRepository
	client *http.Client
	logger *zap.Logger
}

func NewNotificationService(cfg config.TelegramConfig, alerts AlertRepository, logger *zap.Logger) *NotificationService {
	return &NotificationService{cfg: cfg, alerts: alerts, client: &http.Client{Timeout: cfg.Timeout}, logger: logger}
}
func (s *NotificationService) SendTelegram(ctx context.Context, incident *domain.Incident) error {
	if s.cfg.BotToken == "" || s.cfg.AdminChatID == "" {
		return nil
	}
	if incident.Severity < s.cfg.MinSeverity && incident.MLScore < s.cfg.MinScore {
		return nil
	}
	// Иконка по типу угрозы
	icon := "🚨"
	switch incident.ThreatType {
	case "ddos":
		icon = "🚨"
	case "port_scan":
		icon = "🚨"
	case "anomaly":
		icon = "🚨"
	default:
		icon = "🚨"
	}
	// Severity-индикатор: визуальная шкала
	severityBar := ""
	for i := 1; i <= 5; i++ {
		if i <= incident.Severity {
			severityBar += "■"
		} else {
			severityBar += "□"
		}
	}
	msg := fmt.Sprintf("%s *ОБНАРУЖЕНА АНОМАЛИЯ*\n\nТип: *%s*\nКритичность: *%s* %d/5\nОценка ML: *%.2f*\nВремя: *%s* МСК\nID: `%s`\n\n🔗 [Открыть в панели](%s)",
		icon,
		incident.ThreatType,
		severityBar, incident.Severity,
		incident.MLScore,
		incident.CreatedAt.In(time.FixedZone("MSK", 3*60*60)).Format("02.01.2006 15:04:05"),
		incident.ID.String(),
		"https://fluxmon.ru/",
	)
	payload := map[string]any{
		"chat_id":    s.cfg.AdminChatID,
		"text":       msg,
		"parse_mode": "Markdown",
		"reply_markup": map[string]any{
			"inline_keyboard": [][]map[string]string{
				{
					{"text": "🟡 В работу", "callback_data": "investigating:" + incident.ID.String()},
					{"text": "🟢 Решён", "callback_data": "resolved:" + incident.ID.String()},
				},
				{
					{"text": "⚪ Ложное срабатывание", "callback_data": "false_positive:" + incident.ID.String()},
				},
			},
		},
	}
	body, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", s.cfg.BotToken)
	for attempt := 1; attempt <= s.cfg.RetryCount; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := s.client.Do(req)
		if err == nil && resp.StatusCode < 300 {
			if resp.Body != nil {
				resp.Body.Close()
			}
			s.alerts.RecordSent(ctx, incident.ID, "telegram", s.cfg.AdminChatID)
			return nil
		}
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if attempt < s.cfg.RetryCount {
			select {
			case <-time.After(time.Duration(1<<attempt) * time.Second):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	s.alerts.RecordFailed(ctx, incident.ID, "telegram", "max retries exceeded")
	return fmt.Errorf("notification failed")
}