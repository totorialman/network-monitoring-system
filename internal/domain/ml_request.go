package domain

// RawLogForML — сырой лог для передачи в ML-сервис.
// Соответствует RawLog в ml2-http-service/app.py
type RawLogForML struct {
	Timestamp float64 `json:"timestamp"`
	SrcMAC    string  `json:"src_mac,omitempty"`
	DstMAC    string  `json:"dst_mac,omitempty"`
	VLAN      *uint16 `json:"vlan,omitempty"`
	EthType   string  `json:"eth_type,omitempty"`
	SrcIP     string  `json:"src_ip,omitempty"`
	DstIP     string  `json:"dst_ip,omitempty"`
	ICMPType  *uint8  `json:"icmp_type,omitempty"`
	ICMPCode  *uint8  `json:"icmp_code,omitempty"`
	Proto     uint8   `json:"proto,omitempty"`
	TTL       uint8   `json:"ttl,omitempty"`
	SrcPort   uint16  `json:"src_port,omitempty"`
	DstPort   uint16  `json:"dst_port,omitempty"`
	TCPFlags  string  `json:"tcp_flags,omitempty"`
	Length    uint16  `json:"length"`
}

// AnalyzeRequest — запрос с сырыми логами для ML-анализа.
// ML-сервис (ml2-http-service) сам делает агрегацию.
type AnalyzeRequest struct {
	AgentID     string        `json:"agent_id"`
	TimeWindow  float64       `json:"window_seconds"`
	StartTime   string        `json:"start_time"`
	EndTime     string        `json:"end_time"`
	Logs        []RawLogForML `json:"logs"`
}

type AnalyzeResponse struct {
	IsAnomaly      bool     `json:"is_anomaly"`
	AnomalyScore   float64  `json:"anomaly_score"`
	Confidence     float64  `json:"confidence"`
	ThreatType     string   `json:"threat_type"`
	Recommendations []string `json:"recommendations,omitempty"`
}
