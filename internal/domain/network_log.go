package domain

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"net"
	"strconv"
	"time"
)

type NetworkLog struct {
	Timestamp time.Time `json:"timestamp"`
	AgentID   uuid.UUID `json:"agent_id"`
	SrcIP     string    `json:"src_ip" validate:"required,ip"`
	DstIP     string    `json:"dst_ip" validate:"required,ip"`
	SrcPort   uint16    `json:"src_port"`
	DstPort   uint16    `json:"dst_port"`
	Proto     uint8     `json:"proto"`
	TTL       uint8     `json:"ttl"`
	Length    uint16    `json:"length"`
	TCPFlags  string    `json:"tcp_flags"`
	SrcMAC    string    `json:"src_mac"`
	DstMAC    string    `json:"dst_mac"`
	ICMPType  *uint8    `json:"icmp_type"`
	ICMPCode  *uint8    `json:"icmp_code"`
	VLAN      *uint16   `json:"vlan"`
	EthType   string    `json:"eth_type"`
}

// rawNetworkLog — промежуточная структура для десериализации JSON.
// TCPFlagsRaw принимает как строку, так и число.
type rawNetworkLog struct {
	Timestamp   float64         `json:"timestamp"`
	SrcMAC      *string         `json:"src_mac"`
	DstMAC      *string         `json:"dst_mac"`
	VLAN        *uint16         `json:"vlan"`
	EthType     *string         `json:"eth_type"`
	SrcIP       string          `json:"src_ip"`
	DstIP       string          `json:"dst_ip"`
	ICMPType    *uint8          `json:"icmp_type"`
	ICMPCode    *uint8          `json:"icmp_code"`
	Proto       uint8           `json:"proto"`
	TTL         uint8           `json:"ttl"`
	SrcPort     uint16          `json:"src_port"`
	DstPort     uint16          `json:"dst_port"`
	TCPFlagsRaw json.RawMessage `json:"tcp_flags"`
	Length      uint16          `json:"length"`
}

// parseTCPFlags преобразует json.RawMessage в строку.
// Принимает как число (напр. 2), так и строку (напр. "SYN").
func parseTCPFlags(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	// Пробуем строку
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	// Пробуем число
	var n float64
	if err := json.Unmarshal(raw, &n); err == nil {
		return strconv.FormatInt(int64(n), 10)
	}
	// На всякий случай — возвращаем как есть, обрезав кавычки если есть
	val := string(raw)
	if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
		return val[1 : len(val)-1]
	}
	return val
}

func ParseNetworkLog(data []byte, agentID uuid.UUID) (NetworkLog, error) {
	var raw rawNetworkLog
	if err := json.Unmarshal(data, &raw); err != nil {
		return NetworkLog{}, err
	}
	if raw.SrcIP == "" || raw.DstIP == "" {
		return NetworkLog{}, fmt.Errorf("missing required field: src_ip or dst_ip")
	}
	if net.ParseIP(raw.SrcIP) == nil {
		return NetworkLog{}, fmt.Errorf("invalid IP format: %q", raw.SrcIP)
	}
	if net.ParseIP(raw.DstIP) == nil {
		return NetworkLog{}, fmt.Errorf("invalid IP format: %q", raw.DstIP)
	}
	sec := int64(raw.Timestamp)
	nsec := int64((raw.Timestamp - float64(sec)) * 1e9)

	srcMAC := ""
	if raw.SrcMAC != nil {
		srcMAC = *raw.SrcMAC
	}
	dstMAC := ""
	if raw.DstMAC != nil {
		dstMAC = *raw.DstMAC
	}
	ethType := ""
	if raw.EthType != nil {
		ethType = *raw.EthType
	}

	return NetworkLog{
		Timestamp: time.Unix(sec, nsec).UTC(),
		AgentID:   agentID,
		SrcIP:     raw.SrcIP,
		DstIP:     raw.DstIP,
		SrcPort:   raw.SrcPort,
		DstPort:   raw.DstPort,
		Proto:     raw.Proto,
		TTL:       raw.TTL,
		Length:    raw.Length,
		TCPFlags:  parseTCPFlags(raw.TCPFlagsRaw),
		SrcMAC:    srcMAC,
		DstMAC:    dstMAC,
		ICMPType:  raw.ICMPType,
		ICMPCode:  raw.ICMPCode,
		VLAN:      raw.VLAN,
		EthType:   ethType,
	}, nil
}

type ValidationError struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}