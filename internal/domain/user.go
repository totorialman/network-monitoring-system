package domain

import (
	"github.com/google/uuid"
	"time"
)

type User struct {
	ID           uuid.UUID `json:"id"`
	Login        string    `json:"login"`
	PasswordHash string    `json:"-"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type Agent struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	TokenHash      string     `json:"-"`
	TokenPrefix    string     `json:"token_prefix,omitempty"`
	LastSeen       *time.Time `json:"last_seen"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	LogsSentToday  int64      `json:"logs_sent_today,omitempty"`
	LastIncidentAt *time.Time `json:"last_incident_at,omitempty"`
}
type Incident struct {
	ID         uuid.UUID      `json:"id"`
	AgentID    uuid.UUID      `json:"agent_id"`
	AgentName  string         `json:"agent_name,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ThreatType string         `json:"threat_type"`
	Severity   int            `json:"severity"`
	Status     string         `json:"status"`
	MLScore    float64        `json:"ml_score"`
	Details    map[string]any `json:"details,omitempty"`
	Summary    map[string]any `json:"summary,omitempty"`
	ResolvedAt *time.Time     `json:"resolved_at,omitempty"`
	ResolvedBy *uuid.UUID     `json:"resolved_by,omitempty"`
}
type Alert struct {
	ID           uuid.UUID  `json:"id"`
	IncidentID   uuid.UUID  `json:"incident_id"`
	Channel      string     `json:"channel"`
	ChatID       string     `json:"chat_id"`
	SentAt       *time.Time `json:"sent_at"`
	Status       string     `json:"status"`
	ErrorMessage string     `json:"error_message"`
}
