package service

import (
	"context"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"network-monitor-backend/internal/domain"
	"time"
)

type LogRepository interface {
	BatchInsert(context.Context, []domain.NetworkLog) error
}
type IncidentRepository interface {
	Create(context.Context, *domain.Incident) error
}
type Notification interface {
	SendTelegram(context.Context, *domain.Incident) error
}
type LogIngestService struct {
	logs          LogRepository
	incidents     IncidentRepository
	ml            MLClient
	notifications Notification
	logger        *zap.Logger
	window        float64
}

func NewLogIngestService(logs LogRepository, incidents IncidentRepository, ml MLClient, notifications Notification, logger *zap.Logger, window float64) *LogIngestService {
	return &LogIngestService{logs: logs, incidents: incidents, ml: ml, notifications: notifications, logger: logger, window: window}
}

// convertToRawLogs конвертирует domain.NetworkLog в domain.RawLogForML для отправки в ml2-http-service.
func convertToRawLogs(logs []domain.NetworkLog) []domain.RawLogForML {
	out := make([]domain.RawLogForML, len(logs))
	for i, l := range logs {
		ts := float64(l.Timestamp.UnixNano()) / 1e9
		out[i] = domain.RawLogForML{
			Timestamp: ts,
			SrcMAC:    l.SrcMAC,
			DstMAC:    l.DstMAC,
			VLAN:      l.VLAN,
			EthType:   l.EthType,
			SrcIP:     l.SrcIP,
			DstIP:     l.DstIP,
			ICMPType:  l.ICMPType,
			ICMPCode:  l.ICMPCode,
			Proto:     l.Proto,
			TTL:       l.TTL,
			SrcPort:   l.SrcPort,
			DstPort:   l.DstPort,
			TCPFlags:  l.TCPFlags,
			Length:    l.Length,
		}
	}
	return out
}

func (s *LogIngestService) ProcessBatch(logs []domain.NetworkLog, agentID uuid.UUID) {
	ctx := context.Background()

	// 1. Сохраняем сырые логи в ClickHouse
	if err := s.logs.BatchInsert(ctx, logs); err != nil {
		s.logger.Error("clickhouse insert failed", zap.Error(err))
		return
	}

	// 2. Передаём сырые логи в ml2-http-service (он сам делает агрегацию + ML)
	rawLogs := convertToRawLogs(logs)
	windowStart := logs[0].Timestamp.Format(time.RFC3339)
	windowEnd := logs[len(logs)-1].Timestamp.Format(time.RFC3339)

	res, err := s.ml.Analyze(ctx, domain.AnalyzeRequest{
		AgentID:    agentID.String(),
		TimeWindow: s.window,
		StartTime:  windowStart,
		EndTime:    windowEnd,
		Logs:       rawLogs,
	})
	if err != nil {
		s.logger.Warn("ml service call failed", zap.Error(err))
		return
	}

	// 3. Если аномалия — создаём инцидент
	if res.IsAnomaly {
		inc := &domain.Incident{
			AgentID:    agentID,
			ThreatType: res.ThreatType, // классификация в ml2!
			Severity:   calculateSeverity(res.AnomalyScore, len(logs)),
			MLScore:    res.AnomalyScore,
			Details: map[string]any{
				"anomaly_score":   res.AnomalyScore,
				"confidence":      res.Confidence,
				"threat_type":     res.ThreatType,
				"recommendations": res.Recommendations,
				"log_count":       len(logs),
			},
		}
		if err := s.incidents.Create(ctx, inc); err != nil {
			s.logger.Error("failed to create incident", zap.Error(err))
			return
		}
		go s.notifications.SendTelegram(ctx, inc)
	}
}

func calculateSeverity(score float64, n int) int {
	s := 1
	if score >= 0.3 {
		s = 2
	}
	if score >= 0.5 {
		s = 3
	}
	if score >= 0.7 {
		s = 4
	}
	if score >= 0.9 || n > 100000 {
		s = 5
	}
	return s
}
