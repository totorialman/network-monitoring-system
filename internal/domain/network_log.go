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

// flexString принимает из JSON либо строку, либо число (преобразует в строку).
type flexString string

func (f *flexString) UnmarshalJSON(data []byte) error {
	// Пробуем строку
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*f = flexString(s)
		return nil
	}
	// Пробуем число
	var n float64
	if err := json.Unmarshal(data, &n); err == nil {
		*f = flexString(strconv.FormatFloat(n, 'f', -1, 64))
		return nil
	}
	return fmt.Errorf("flexString: expected string or number, got %s", string(data))
}

func (f flexString) String() string { return string(f) }

// nilableString принимает из JSON строку или null (null → пустая строка).
type nilableString string

func (n *nilableString) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*n = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*n = nilableString(s)
	return nil
}

func (n nilableString) String() string { return string(n) }

type rawNetworkLog struct {
	Timestamp float64      `json:"timestamp"`
	SrcMAC    nilableString `json:"src_mac"`
	DstMAC    nilableString `json:"dst_mac"`
	VLAN      *uint16      `json:"vlan"`
	EthType   nilableString `json:"eth_type"`
	SrcIP     string       `json:"src_ip"`
	DstIP     string       `json:"dst_ip"`
	ICMPType  *uint8       `json:"icmp_type"`
	ICMPCode  *uint8       `json:"icmp_code"`
	Proto     uint8        `json:"proto"`
	TTL       uint8        `json:"ttl"`
	SrcPort   uint16       `json:"src_port"`
	DstPort   uint16       `json:"dst_port"`
	TCPFlags  flexString   `json:"tcp_flags"`
	Length    uint16       `json:"length"`
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
		TCPFlags:  raw.TCPFlags.String(),
		SrcMAC:    raw.SrcMAC.String(),
		DstMAC:    raw.DstMAC.String(),
		ICMPType:  raw.ICMPType,
		ICMPCode:  raw.ICMPCode,
		VLAN:      raw.VLAN,
		EthType:   raw.EthType.String(),
	}, nil
}

type ValidationError struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}