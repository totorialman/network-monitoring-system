package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	_ "github.com/ClickHouse/clickhouse-go/v2"
	"network-monitor-backend/internal/config"
	"network-monitor-backend/internal/domain"
)

type LogRepo struct{ db *sql.DB }

func New(cfg config.ClickHouseConfig) (*LogRepo, error) {
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%s/%s?dial_timeout=10s", cfg.User, cfg.Password, cfg.Host, cfg.Port, cfg.Database)
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, err
	}
	return &LogRepo{db: db}, nil
}
func (r *LogRepo) Close() error                   { return r.db.Close() }
func (r *LogRepo) Ping(ctx context.Context) error { return r.db.PingContext(ctx) }
func (r *LogRepo) InitSchema(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS network_logs (
			timestamp DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
			agent_id UUID,
			src_ip IPv4,
			dst_ip IPv4,
			src_port UInt16,
			dst_port UInt16,
			proto UInt8,
			ttl UInt8,
			length UInt16,
			tcp_flags String,
			src_mac String,
			dst_mac String,
			icmp_type Nullable(UInt8),
			icmp_code Nullable(UInt8),
			vlan Nullable(UInt16),
			eth_type String,
			hour DateTime MATERIALIZED toStartOfHour(timestamp),
			day Date MATERIALIZED toDate(timestamp)
		) ENGINE = MergeTree
		PARTITION BY toYYYYMM(timestamp)
		ORDER BY (agent_id, timestamp, src_ip)
		TTL toDateTime(timestamp) + INTERVAL 90 DAY
		SETTINGS index_granularity = 8192, compress_primary_key = true
	`)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, `
		CREATE MATERIALIZED VIEW IF NOT EXISTS network_logs_hourly 
		ENGINE = SummingMergeTree 
		PARTITION BY toYYYYMM(hour) 
		ORDER BY (agent_id, hour, src_ip) 
		AS SELECT 
			agent_id, 
			toStartOfHour(timestamp) AS hour, 
			src_ip, 
			count() AS packet_count, 
			uniq(dst_ip) AS unique_dst_ips, 
			uniq(dst_port) AS unique_dst_ports, 
			avg(length) AS avg_length, 
			sum(length) AS total_bytes 
		FROM network_logs 
		GROUP BY agent_id, hour, src_ip
	`)
	return err
}
func (r *LogRepo) BatchInsert(ctx context.Context, logs []domain.NetworkLog) error {
	if len(logs) == 0 {
		return nil
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO network_logs (timestamp,agent_id,src_ip,dst_ip,src_port,dst_port,proto,ttl,length,tcp_flags,src_mac,dst_mac,icmp_type,icmp_code,vlan,eth_type) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, l := range logs {
		if _, err := stmt.ExecContext(ctx, l.Timestamp, l.AgentID, l.SrcIP, l.DstIP, l.SrcPort, l.DstPort, l.Proto, l.TTL, l.Length, l.TCPFlags, l.SrcMAC, l.DstMAC, l.ICMPType, l.ICMPCode, l.VLAN, l.EthType); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
func (r *LogRepo) Count(ctx context.Context) int64 {
	var n int64

	err := r.db.QueryRowContext(ctx, `SELECT count() FROM network_logs`).Scan(&n)
	if err != nil {
		fmt.Printf("ERROR: clickhouse count query failed: %v\n", err)
		return 0
	}
	
	return n
}
func (r *LogRepo) RawSample(ctx context.Context, agentID string, limit int) []map[string]any {
	return []map[string]any{}
}
