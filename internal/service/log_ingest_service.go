package service

import (
	"context"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"network-monitor-backend/internal/domain"
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

// WsBroadcaster — интерфейс для WebSocket-рассылки событий.
// Реализован в handler.WsHub, чтобы избежать циклического импорта.
type WsBroadcaster interface {
	Broadcast(event interface{})
}

type LogIngestService struct {
	logs          LogRepository
	incidents     IncidentRepository
	ml            MLClient
	notifications Notification
	ws            WsBroadcaster
	logger        *zap.Logger
	window        float64
}

func NewLogIngestService(
	logs LogRepository,
	incidents IncidentRepository,
	ml MLClient,
	notifications Notification,
	ws WsBroadcaster,
	logger *zap.Logger,
	window float64,
) *LogIngestService {
	return &LogIngestService{
		logs:          logs,
		incidents:     incidents,
		ml:            ml,
		notifications: notifications,
		ws:            ws,
		logger:        logger,
		window:        window,
	}
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

// WsIncidentPayload — данные инцидента для WebSocket-уведомления.
type WsIncidentPayload struct {
	ID         string  `json:"id"`
	AgentID    string  `json:"agent_id"`
	ThreatType string  `json:"threat_type"`
	Severity   int     `json:"severity"`
	MLScore    float64 `json:"ml_score"`
	Status     string  `json:"status"`
	LogCount   int     `json:"log_count"`
}

func (s *LogIngestService) ProcessBatch(logs []domain.NetworkLog, agentID uuid.UUID) {
	ctx := context.Background()

	// 1. Сохраняем сырые логи в ClickHouse
	if err := s.logs.BatchInsert(ctx, logs); err != nil {
		s.logger.Error("clickhouse insert failed", zap.Error(err))
		return
	}

	// Извлекаем топ подозрительных IP из логов (для top_sources на дашборде)
	topIPs := extractTopSuspiciousIPs(logs, 3)

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

	var anomalyResult *domain.AnalyzeResponse
	if err != nil {
		s.logger.Warn("ml service call failed, using local heuristics", zap.Error(err))
		anomalyResult = localHeuristicCheck(logs, s.window)
	} else {
		anomalyResult = res
	}

	// 3. Создаём инцидент для КАЖДОГО батча логов (независимо от ML)
	threatType := "traffic"
	mlScore := 0.0
	detectionMethod := "none"

	if anomalyResult != nil {
		if anomalyResult.ThreatType != "" {
			threatType = anomalyResult.ThreatType
		}
		mlScore = anomalyResult.AnomalyScore
		if anomalyResult.DetectionMethod != "" {
			detectionMethod = anomalyResult.DetectionMethod
		}
		if anomalyResult.IsAnomaly {
			mlScore = anomalyResult.AnomalyScore
		}
	}

	details := map[string]any{
		"anomaly_score":    mlScore,
		"confidence":       0.0,
		"threat_type":      threatType,
		"detection_method": detectionMethod,
		"log_count":        len(logs),
	}
	if anomalyResult != nil && anomalyResult.IsAnomaly {
		details["confidence"] = anomalyResult.Confidence
		if len(anomalyResult.Recommendations) > 0 {
			details["recommendations"] = anomalyResult.Recommendations
		}
	}
	if len(topIPs) > 0 {
		details["top_suspicious_ips"] = stringsJoin(topIPs, ", ")
	}

	inc := &domain.Incident{
		AgentID:    agentID,
		ThreatType: threatType,
		Severity:   calculateSeverity(mlScore, len(logs)),
		MLScore:    mlScore,
		Details:    details,
	}

	if err := s.incidents.Create(ctx, inc); err != nil {
		s.logger.Error("failed to create incident", zap.Error(err))
		return
	}

	// 4. Отправляем WebSocket-уведомление всем подключённым клиентам
	if s.ws != nil {
		s.ws.Broadcast(map[string]any{
			"type": "new_incident",
			"payload": WsIncidentPayload{
				ID:         inc.ID.String(),
				AgentID:    agentID.String(),
				ThreatType: inc.ThreatType,
				Severity:   inc.Severity,
				MLScore:    inc.MLScore,
				Status:     inc.Status,
				LogCount:   len(logs),
			},
		})
	}

	// 5. Telegram-уведомление (best-effort)
	go s.notifications.SendTelegram(ctx, inc)
}

// extractTopSuspiciousIPs извлекает топ-N самых частых src_ip из логов.
func extractTopSuspiciousIPs(logs []domain.NetworkLog, topN int) []string {
	counts := map[string]int{}
	for _, l := range logs {
		if l.SrcIP != "" {
			counts[l.SrcIP]++
		}
	}
	type ipCount struct {
		ip  string
		cnt int
	}
	var sorted []ipCount
	for ip, cnt := range counts {
		sorted = append(sorted, ipCount{ip, cnt})
	}
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].cnt > sorted[i].cnt {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	var out []string
	for i := 0; i < topN && i < len(sorted); i++ {
		out = append(out, sorted[i].ip)
	}
	return out
}

// localHeuristicCheck выполняет локальную эвристическую проверку при недоступности ML-сервиса.
func localHeuristicCheck(logs []domain.NetworkLog, windowSeconds float64) *domain.AnalyzeResponse {
	if len(logs) == 0 {
		return &domain.AnalyzeResponse{IsAnomaly: false}
	}
	srcIPs := map[string]int{}
	dstPorts := map[uint16]int{}
	for _, l := range logs {
		if l.SrcIP != "" {
			srcIPs[l.SrcIP]++
		}
		if l.DstPort > 0 {
			dstPorts[l.DstPort]++
		}
	}
	packetCount := len(logs)
	uniqueSrcIP := len(srcIPs)
	uniqueDstPorts := len(dstPorts)

	startTs := float64(logs[0].Timestamp.UnixNano()) / 1e9
	endTs := float64(logs[len(logs)-1].Timestamp.UnixNano()) / 1e9
	duration := endTs - startTs
	if duration < 0.001 {
		duration = windowSeconds
	}
	pps := float64(packetCount) / duration

	isAnomaly := (pps > 1000 && uniqueSrcIP <= 5) || uniqueDstPorts > 50
	if !isAnomaly {
		return &domain.AnalyzeResponse{IsAnomaly: false}
	}
	threatType := "anomaly"
	if pps > 1000 && uniqueSrcIP <= 5 {
		threatType = "ddos"
	} else if uniqueDstPorts > 50 {
		threatType = "port_scan"
	}
	return &domain.AnalyzeResponse{
		IsAnomaly:       true,
		AnomalyScore:    0.0,
		Confidence:      0.85,
		ThreatType:      threatType,
		DetectionMethod: "heuristic_local",
	}
}

func stringsJoin(ss []string, sep string) string {
	if len(ss) == 0 {
		return ""
	}
	r := ss[0]
	for i := 1; i < len(ss); i++ {
		r += sep + ss[i]
	}
	return r
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