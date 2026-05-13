package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"network-monitor-backend/internal/domain"
	"strings"
	"time"
)

type UserRepo struct{ db *sql.DB }
type AgentRepo struct{ db *sql.DB }
type IncidentRepo struct{ db *sql.DB }
type AlertRepo struct{ db *sql.DB }

func NewUserRepo(db *sql.DB) *UserRepo         { return &UserRepo{db: db} }
func NewAgentRepo(db *sql.DB) *AgentRepo       { return &AgentRepo{db: db} }
func NewIncidentRepo(db *sql.DB) *IncidentRepo { return &IncidentRepo{db: db} }
func NewAlertRepo(db *sql.DB) *AlertRepo       { return &AlertRepo{db: db} }

func (r *UserRepo) FindByLogin(ctx context.Context, login string) (*domain.User, error) {
	u := domain.User{}
	err := r.db.QueryRowContext(ctx, `SELECT id, login, password_hash, role, created_at, updated_at FROM users WHERE login=$1`, login).Scan(&u.ID, &u.Login, &u.PasswordHash, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}
func (r *UserRepo) EnsureAdmin(ctx context.Context, login, passwordHash string) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO users(login, password_hash, role) VALUES($1,$2,'admin') ON CONFLICT(login) DO NOTHING`, login, passwordHash)
	return err
}
func (r *AgentRepo) Create(ctx context.Context, name, tokenHash, tokenPrefix string) (*domain.Agent, error) {
	a := domain.Agent{}
	err := r.db.QueryRowContext(ctx, `INSERT INTO agents(name, token_hash, token_prefix) VALUES($1,$2,$3) RETURNING id,name,token_hash,token_prefix,last_seen,status,created_at`, name, tokenHash, tokenPrefix).Scan(&a.ID, &a.Name, &a.TokenHash, &a.TokenPrefix, &a.LastSeen, &a.Status, &a.CreatedAt)
	return &a, err
}
func (r *AgentRepo) FindByTokenHash(ctx context.Context, tokenHash string) (*domain.Agent, error) {
	a := domain.Agent{}
	err := r.db.QueryRowContext(ctx, `SELECT id,name,token_hash,COALESCE(token_prefix,''),last_seen,status,created_at FROM agents WHERE token_hash=$1 AND status='active'`, tokenHash).Scan(&a.ID, &a.Name, &a.TokenHash, &a.TokenPrefix, &a.LastSeen, &a.Status, &a.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}
func (r *AgentRepo) Touch(ctx context.Context, id uuid.UUID) {
	_, _ = r.db.ExecContext(ctx, `UPDATE agents SET last_seen=NOW() WHERE id=$1`, id)
}
func (r *AgentRepo) List(ctx context.Context) ([]domain.Agent, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT a.id,a.name,COALESCE(a.token_prefix,''),a.last_seen,a.status,a.created_at,COALESCE((SELECT COUNT(*) FROM incidents i WHERE i.agent_id=a.id AND i.created_at::date=current_date),0), (SELECT MAX(created_at) FROM incidents i WHERE i.agent_id=a.id) FROM agents a ORDER BY a.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Agent
	for rows.Next() {
		var a domain.Agent
		if err := rows.Scan(&a.ID, &a.Name, &a.TokenPrefix, &a.LastSeen, &a.Status, &a.CreatedAt, &a.LogsSentToday, &a.LastIncidentAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type IncidentFilters struct {
	Page, Limit                                          int
	Status, ThreatType, AgentID, From, To, SortBy, Order string
	SeverityMin, SeverityMax                             int
}

func (r *IncidentRepo) Create(ctx context.Context, in *domain.Incident) error {
	b, _ := json.Marshal(in.Details)
	return r.db.QueryRowContext(ctx, `INSERT INTO incidents(agent_id, threat_type, severity, ml_score, details) VALUES($1,$2,$3,$4,$5) RETURNING id,created_at,status`, in.AgentID, in.ThreatType, in.Severity, in.MLScore, b).Scan(&in.ID, &in.CreatedAt, &in.Status)
}
func (r *IncidentRepo) List(ctx context.Context, f IncidentFilters) ([]domain.Incident, int64, error) {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Limit < 1 {
		f.Limit = 50
	}
	if f.Limit > 200 {
		f.Limit = 200
	}
	where, args := buildIncidentWhere(f)
	countQ := `SELECT COUNT(*) FROM incidents i ` + where
	var total int64
	if err := r.db.QueryRowContext(ctx, countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	sort := safe(f.SortBy, map[string]bool{"created_at": true, "severity": true, "ml_score": true}, "created_at")
	order := strings.ToUpper(safe(f.Order, map[string]bool{"asc": true, "desc": true}, "desc"))
	q := fmt.Sprintf(`SELECT i.id,i.agent_id,COALESCE(a.name,''),i.created_at,i.threat_type,i.severity,i.status,i.ml_score,COALESCE(i.details,'{}'::jsonb) FROM incidents i LEFT JOIN agents a ON a.id=i.agent_id %s ORDER BY i.%s %s LIMIT $%d OFFSET $%d`, where, sort, order, len(args)+1, len(args)+2)
	args = append(args, f.Limit, (f.Page-1)*f.Limit)
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Incident
	for rows.Next() {
		var in domain.Incident
		var details []byte
		if err := rows.Scan(&in.ID, &in.AgentID, &in.AgentName, &in.CreatedAt, &in.ThreatType, &in.Severity, &in.Status, &in.MLScore, &details); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(details, &in.Details)
		in.Summary = in.Details
		out = append(out, in)
	}
	return out, total, rows.Err()
}
func (r *IncidentRepo) Get(ctx context.Context, id uuid.UUID) (*domain.Incident, error) {
	var in domain.Incident
	var details []byte
	err := r.db.QueryRowContext(ctx, `SELECT i.id,i.agent_id,COALESCE(a.name,''),i.created_at,i.threat_type,i.severity,i.status,i.ml_score,COALESCE(i.details,'{}'::jsonb),i.resolved_at,i.resolved_by FROM incidents i LEFT JOIN agents a ON a.id=i.agent_id WHERE i.id=$1`, id).Scan(&in.ID, &in.AgentID, &in.AgentName, &in.CreatedAt, &in.ThreatType, &in.Severity, &in.Status, &in.MLScore, &details, &in.ResolvedAt, &in.ResolvedBy)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(details, &in.Details)
	return &in, nil
}
func (r *IncidentRepo) UpdateStatus(ctx context.Context, id, userID uuid.UUID, status string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE incidents
SET
    status = $1::varchar(30),
    resolved_at = CASE
        WHEN $1::varchar(30) IN ('resolved','false_positive') THEN NOW()
        ELSE resolved_at
    END,
    resolved_by = CASE
        WHEN $1::varchar(30) IN ('resolved','false_positive') THEN $2::uuid
        ELSE resolved_by
    END
WHERE id = $3::uuid`, status, userID, id)
	return err
}
func (r *IncidentRepo) Stats(ctx context.Context) (map[string]any, error) {
	res := map[string]any{}
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(*) FILTER (WHERE status='new'), COALESCE(AVG(ml_score),0) FROM incidents`).Scan(ptr(&res, "total_incidents"), ptr(&res, "new_incidents"), ptr(&res, "avg_ml_score"))
	var active int64
	_ = r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE status='active'`).Scan(&active)
	res["active_agents"] = active
	rows, _ := r.db.QueryContext(ctx, `SELECT threat_type, COUNT(*) FROM incidents GROUP BY threat_type`)
	dist := map[string]int64{"ddos": 0, "port_scan": 0, "anomaly": 0, "other": 0}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var k string
			var v int64
			_ = rows.Scan(&k, &v)
			dist[k] = v
		}
	}
	res["threat_distribution"] = dist
	return res, nil
}
func (r *AlertRepo) RecordSent(ctx context.Context, incidentID uuid.UUID, channel, chatID string) {
	_, _ = r.db.ExecContext(ctx, `INSERT INTO alerts(incident_id,channel,chat_id,sent_at,status) VALUES($1,$2,$3,NOW(),'sent')`, incidentID, channel, chatID)
}
func (r *AlertRepo) RecordFailed(ctx context.Context, incidentID uuid.UUID, channel, message string) {
	_, _ = r.db.ExecContext(ctx, `INSERT INTO alerts(incident_id,channel,error_message,status) VALUES($1,$2,$3,'failed')`, incidentID, channel, message)
}

func buildIncidentWhere(f IncidentFilters) (string, []any) {
	var parts []string
	var args []any
	add := func(cond string, val any) {
		args = append(args, val)
		parts = append(parts, fmt.Sprintf(cond, len(args)))
	}
	if f.Status != "" {
		add("i.status=$%d", f.Status)
	}
	if f.ThreatType != "" {
		add("i.threat_type=$%d", f.ThreatType)
	}
	if f.AgentID != "" {
		add("i.agent_id=$%d", f.AgentID)
	}
	if f.SeverityMin > 0 {
		add("i.severity>=$%d", f.SeverityMin)
	}
	if f.SeverityMax > 0 {
		add("i.severity<=$%d", f.SeverityMax)
	}
	if f.From != "" {
		add("i.created_at>=$%d", f.From)
	}
	if f.To != "" {
		add("i.created_at<=$%d", f.To)
	}
	if len(parts) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(parts, " AND "), args
}
func safe(v string, allowed map[string]bool, fallback string) string {
	if allowed[strings.ToLower(v)] {
		return strings.ToLower(v)
	}
	return fallback
}
func ptr(m *map[string]any, key string) any { var v float64; (*m)[key] = v; return &v }

var _ = time.Now
