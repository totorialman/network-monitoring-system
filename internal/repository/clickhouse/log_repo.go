package clickhouse

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/url"
	"sync/atomic"

	_ "github.com/ClickHouse/clickhouse-go/v2"
	"network-monitor-backend/internal/config"
	"network-monitor-backend/internal/domain"
)

type LogRepo struct {
	db             *sql.DB
	lastKnownCount atomic.Int64
}

func New(cfg config.ClickHouseConfig) (*LogRepo, error) {
	dsn := fmt.Sprintf("clickhouse://%s:%s@%s:%s/%s?dial_timeout=10s",
		url.QueryEscape(cfg.User),
		url.QueryEscape(cfg.Password),
		cfg.Host, cfg.Port, cfg.Database)
	db, err := sql.Open("clickhouse", dsn)
	if err != nil {
		return nil, err
	}
	repo := &LogRepo{db: db}
	return repo, nil
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
	// После успешной вставки атомарно увеличиваем счётчик
	r.lastKnownCount.Add(int64(len(logs)))
	return tx.Commit()
}

// Count возвращает актуальное количество сырых логов в ClickHouse.
// При первом вызове или после перезапуска синхронизируется с ClickHouse.
func (r *LogRepo) Count(ctx context.Context) int64 {
	var n int64
	err := r.db.QueryRowContext(ctx, `SELECT count() FROM network_logs`).Scan(&n)
	if err != nil {
		if cached := r.lastKnownCount.Load(); cached > 0 {
			return cached
		}
		return 0
	}
	r.lastKnownCount.Store(n)
	return n
}

// RawSample возвращает сырые логи из ClickHouse для указанного агента.
func (r *LogRepo) RawSample(ctx context.Context, agentID string, limit int) []map[string]any {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	// Передаём agentID как строку, используем toUUID() на стороне ClickHouse
	rows, err := r.db.QueryContext(ctx, `
		SELECT
			timestamp,
			src_ip,
			dst_ip,
			src_port,
			dst_port,
			proto,
			ttl,
			length,
			tcp_flags,
			icmp_type,
			icmp_code,
			src_mac,
			dst_mac,
			vlan,
			eth_type
		FROM network_logs
		WHERE agent_id = toUUID(?)
		ORDER BY timestamp DESC
		LIMIT ?
	`, agentID, limit)
	if err != nil {
		log.Printf("ERROR: clickhouse RawSample query failed for agent_id=%s: %v", agentID, err)
		return []map[string]any{}
	}
	defer rows.Close()

	var out []map[string]any
	for rows.Next() {
		var (
			timestamp                                     sql.NullTime
			srcIP, dstIP, tcpFlags, srcMAC, dstMAC, ethType string
			srcPort, dstPort, proto, ttl, length          uint16
			icmpType, icmpCode                            *uint8
			vlan                                          *uint16
		)
		if err := rows.Scan(&timestamp, &srcIP, &dstIP, &srcPort, &dstPort, &proto, &ttl, &length, &tcpFlags, &icmpType, &icmpCode, &srcMAC, &dstMAC, &vlan, &ethType); err != nil {
			continue
		}
		row := map[string]any{
			"src_ip":    srcIP,
			"dst_ip":    dstIP,
			"src_port":  srcPort,
			"dst_port":  dstPort,
			"proto":     proto,
			"ttl":       ttl,
			"length":    length,
			"tcp_flags": tcpFlags,
			"src_mac":   srcMAC,
			"dst_mac":   dstMAC,
			"eth_type":  ethType,
		}
		if timestamp.Valid {
			row["timestamp"] = timestamp.Time.UTC().Format("2006-01-02T15:04:05.000Z")
		}
		if icmpType != nil {
			row["icmp_type"] = *icmpType
		}
		if icmpCode != nil {
			row["icmp_code"] = *icmpCode
		}
		if vlan != nil {
			row["vlan"] = *vlan
		}
		out = append(out, row)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}