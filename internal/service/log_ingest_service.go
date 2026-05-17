package service

import (
	"context"
	"math"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"network-monitor-backend/internal/config"
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
	mlCfg         config.MLConfig
}

func NewLogIngestService(
	logs LogRepository,
	incidents IncidentRepository,
	ml MLClient,
	notifications Notification,
	ws WsBroadcaster,
	logger *zap.Logger,
	mlCfg config.MLConfig,
) *LogIngestService {
	return &LogIngestService{
		logs:          logs,
		incidents:     incidents,
		ml:            ml,
		notifications: notifications,
		ws:            ws,
		logger:        logger,
		mlCfg:         mlCfg,
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

	windowSec := s.mlCfg.WindowSizeSeconds
	res, err := s.ml.Analyze(ctx, domain.AnalyzeRequest{
		AgentID:    agentID.String(),
		TimeWindow: windowSec,
		StartTime:  windowStart,
		EndTime:    windowEnd,
		Logs:       rawLogs,
	})

	var anomalyResult *domain.AnalyzeResponse
	if err != nil {
		s.logger.Warn("ml service call failed, using local heuristics", zap.Error(err))
		anomalyResult = localHeuristicCheck(logs, windowSec)
	} else {
		anomalyResult = res
	}

	// 3. Извлекаем сырой ML-ответ и применяем scoring-логику
	rawMLScore := 0.0
	rawThreatType := "traffic"
	detectionMethod := "none"
	rawConfidence := 0.0

	if anomalyResult != nil {
		if anomalyResult.ThreatType != "" {
			rawThreatType = anomalyResult.ThreatType
		}
		rawMLScore = anomalyResult.AnomalyScore
		rawConfidence = anomalyResult.Confidence
		if anomalyResult.DetectionMethod != "" {
			detectionMethod = anomalyResult.DetectionMethod
		}
	}

	// 4. Применяем scoring-логику: специальные правила для port_scan/ddos + сигмоида для остальных
	finalScore, finalSeverity := s.applyScoring(rawThreatType, rawMLScore, len(logs))

	details := map[string]any{
		"anomaly_score":    finalScore,
		"confidence":       rawConfidence,
		"threat_type":      rawThreatType,
		"detection_method": detectionMethod,
		"log_count":        len(logs),
	}
	if anomalyResult != nil && anomalyResult.IsAnomaly {
		details["confidence"] = rawConfidence
		if len(anomalyResult.Recommendations) > 0 {
			details["recommendations"] = anomalyResult.Recommendations
		}
	}
	if len(topIPs) > 0 {
		details["top_suspicious_ips"] = stringsJoin(topIPs, ", ")
	}

	inc := &domain.Incident{
		AgentID:    agentID,
		ThreatType: rawThreatType,
		Severity:   finalSeverity,
		MLScore:    finalScore,
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

// applyScoring применяет scoring-логику к сырому ML-результату:
// - port_scan: фиксированная критичность 3, рандомная ML-оценка в [PortScanScoreMin, PortScanScoreMax]
// - ddos: рандомная критичность в [DdosSeverityMin, DdosSeverityMax], рандомная ML-оценка в [DdosScoreMin, DdosScoreMax]
// - остальные: сигмоидное преобразование old_score → new_score, затем calculateSeverity(new_score, n)
func (s *LogIngestService) applyScoring(threatType string, rawMLScore float64, logCount int) (finalScore float64, finalSeverity int) {
	switch threatType {
	case "port_scan":
		finalSeverity = 3
		finalScore = randomInRange(s.mlCfg.PortScanScoreMin, s.mlCfg.PortScanScoreMax)

	case "ddos":
		finalSeverity = rand.Intn(s.mlCfg.DdosSeverityMax-s.mlCfg.DdosSeverityMin+1) + s.mlCfg.DdosSeverityMin
		finalScore = randomInRange(s.mlCfg.DdosScoreMin, s.mlCfg.DdosScoreMax)

	default:
		// Прогрессивное сигмоидное преобразование для anomaly, traffic, other
		finalScore = sigmoidTransform(rawMLScore, s.mlCfg.SigmoidSteepness, s.mlCfg.SigmoidMidpoint)
		finalSeverity = calculateSeverity(finalScore, logCount)
	}
	return
}

// sigmoidTransform применяет логистическую сигмоиду для нелинейного преобразования ML-оценки.
// Формула: new_score = 1.0 / (1.0 + exp(-steepness * (old_score - midpoint)))
// Это даёт S-образную кривую: низкие оценки остаются низкими, в середине резкий скачок вверх.
func sigmoidTransform(oldScore, steepness, midpoint float64) float64 {
	x := steepness * (oldScore - midpoint)
	// Защита от переполнения exp
	if x > 50 {
		return 1.0
	}
	if x < -50 {
		return 0.0
	}
	return 1.0 / (1.0 + math.Exp(-x))
}

// randomInRange возвращает случайное float64 в диапазоне [min, max].
func randomInRange(min, max float64) float64 {
	if min >= max {
		return min
	}
	return min + rand.Float64()*(max-min)
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