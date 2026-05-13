package service

import (
	"context"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"math"
	"network-monitor-backend/internal/domain"
	"sort"
	"strings"
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
func (s *LogIngestService) ProcessBatch(logs []domain.NetworkLog, agentID uuid.UUID) {
	ctx := context.Background()
	if err := s.logs.BatchInsert(ctx, logs); err != nil {
		s.logger.Error("clickhouse insert failed", zap.Error(err))
		return
	}
	features, start, end := ExtractFeatures(logs, s.window)
	res, err := s.ml.Analyze(ctx, domain.AnalyzeRequest{AgentID: agentID, TimeWindow: s.window, StartTime: start, EndTime: end, Features: features})
	if err != nil {
		s.logger.Warn("ml service call failed", zap.Error(err))
		return
	}
	if res.IsAnomaly {
		inc := &domain.Incident{AgentID: agentID, ThreatType: classifyThreat(res, features), Severity: calculateSeverity(res.AnomalyScore, len(logs)), MLScore: res.AnomalyScore, Details: map[string]any{"top_suspicious_ips": res.TopSuspiciousIPs, "top_targeted_ports": res.TopTargetedPorts, "recommendations": res.Recommendations, "packet_count": features.PacketCount, "unique_src_ips": features.UniqueSrcIPs, "unique_dst_ports": features.UniqueDstPorts, "packets_per_second": features.PacketsPerSecond, "entropy_dst_ports": features.DstPortEntropy}}
		if err := s.incidents.Create(ctx, inc); err != nil {
			s.logger.Error("failed to create incident", zap.Error(err))
			return
		}
		go s.notifications.SendTelegram(ctx, inc)
	}
}
func ExtractFeatures(logs []domain.NetworkLog, window float64) (domain.FeatureVector, time.Time, time.Time) {
	f := domain.FeatureVector{MinLength: math.MaxUint16}
	if len(logs) == 0 {
		return f, time.Now(), time.Now()
	}
	src, dst, dp, sp := map[string]bool{}, map[string]bool{}, map[uint16]int{}, map[uint16]bool{}
	start, end := logs[0].Timestamp, logs[0].Timestamp
	var lengthSum, ttlSum uint64
	for _, l := range logs {
		f.PacketCount++
		if l.Timestamp.Before(start) {
			start = l.Timestamp
		}
		if l.Timestamp.After(end) {
			end = l.Timestamp
		}
		src[l.SrcIP] = true
		dst[l.DstIP] = true
		dp[l.DstPort]++
		sp[l.SrcPort] = true
		switch l.Proto {
		case 6:
			f.ProtoTCP++
		case 17:
			f.ProtoUDP++
		case 1:
			f.ProtoICMP++
			f.ICMPCount++
		}
		flags := strings.ToUpper(l.TCPFlags)
		if strings.Contains(flags, "SYN") {
			f.TCPFlagsSYN++
		}
		if strings.Contains(flags, "ACK") {
			f.TCPFlagsACK++
		}
		if strings.Contains(flags, "FIN") {
			f.TCPFlagsFIN++
		}
		if strings.Contains(flags, "RST") {
			f.TCPFlagsRST++
		}
		lengthSum += uint64(l.Length)
		ttlSum += uint64(l.TTL)
		if l.Length < f.MinLength {
			f.MinLength = l.Length
		}
		if l.Length > f.MaxLength {
			f.MaxLength = l.Length
		}
	}
	f.UniqueSrcIPs = uint64(len(src))
	f.UniqueDstIPs = uint64(len(dst))
	f.UniqueDstPorts = uint64(len(dp))
	f.UniqueSrcPorts = uint64(len(sp))
	f.AvgLength = float64(lengthSum) / float64(len(logs))
	f.AvgTTL = float64(ttlSum) / float64(len(logs))
	dur := end.Sub(start).Seconds()
	if dur <= 0 {
		dur = window
	}
	f.PacketsPerSecond = float64(len(logs)) / dur
	f.ConnectionSpread = float64(len(dst)) / float64(len(logs))
	f.DstPortEntropy = entropy(dp, len(logs))
	return f, start, end
}
func entropy(counts map[uint16]int, total int) float64 {
	if total == 0 {
		return 0
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	if len(counts) > 1 {
		h /= math.Log2(float64(len(counts)))
	}
	return h
}
func classifyThreat(r *domain.AnalyzeResponse, f domain.FeatureVector) string {
	if r.ThreatType != "" {
		return r.ThreatType
	}
	if f.UniqueDstPorts > 100 {
		return "port_scan"
	}
	if f.PacketsPerSecond > 1000 {
		return "ddos"
	}
	return "anomaly"
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

var _ = sort.Ints
