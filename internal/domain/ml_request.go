package domain

import (
	"github.com/google/uuid"
	"time"
)

type AnalyzeRequest struct {
	AgentID    uuid.UUID     `json:"agent_id"`
	TimeWindow float64       `json:"window_seconds"`
	StartTime  time.Time     `json:"start_time"`
	EndTime    time.Time     `json:"end_time"`
	Features   FeatureVector `json:"features"`
}
type FeatureVector struct {
	PacketCount      uint64  `json:"packet_count"`
	PacketsPerSecond float64 `json:"pps"`
	UniqueSrcIPs     uint64  `json:"unique_src_ips"`
	UniqueDstIPs     uint64  `json:"unique_dst_ips"`
	UniqueDstPorts   uint64  `json:"unique_dst_ports"`
	UniqueSrcPorts   uint64  `json:"unique_src_ports"`
	ProtoTCP         uint64  `json:"proto_tcp"`
	ProtoUDP         uint64  `json:"proto_udp"`
	ProtoICMP        uint64  `json:"proto_icmp"`
	TCPFlagsSYN      uint64  `json:"tcp_syn"`
	TCPFlagsACK      uint64  `json:"tcp_ack"`
	TCPFlagsFIN      uint64  `json:"tcp_fin"`
	TCPFlagsRST      uint64  `json:"tcp_rst"`
	AvgLength        float64 `json:"avg_length"`
	MinLength        uint16  `json:"min_length"`
	MaxLength        uint16  `json:"max_length"`
	AvgTTL           float64 `json:"avg_ttl"`
	DstPortEntropy   float64 `json:"dst_port_entropy"`
	ICMPCount        uint64  `json:"icmp_count"`
	ConnectionSpread float64 `json:"connection_spread"`
}
type AnalyzeResponse struct {
	IsAnomaly        bool     `json:"is_anomaly"`
	AnomalyScore     float64  `json:"anomaly_score"`
	Confidence       float64  `json:"confidence"`
	ThreatType       string   `json:"threat_type"`
	TopSuspiciousIPs []string `json:"top_suspicious_ips"`
	TopTargetedPorts []uint16 `json:"top_targeted_ports"`
	Recommendations  []string `json:"recommendations"`
}
