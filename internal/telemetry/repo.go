package telemetry

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
)

type Retention struct {
	UsageDays int
	FlowsDays int
	DNSDays   int
}

// schema возвращает DDL таблиц
func schema(r Retention) []string {
	return []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS peer_usage (
			ts         DateTime('UTC'),
			cluster_id UUID,
			node_id    UUID,
			peer_id    UUID,
			rx         UInt64,
			tx         UInt64
		) ENGINE = SummingMergeTree((rx, tx))
		PARTITION BY toYYYYMM(ts)
		ORDER BY (peer_id, ts, node_id)
		TTL ts + INTERVAL %d DAY`, r.UsageDays),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS flows (
			minute       DateTime('UTC'),
			cluster_id   UUID,
			node_id      UUID,
			peer_id      UUID,
			proto        UInt8,
			dst_ip       IPv6,
			dst_port     UInt16,
			domain       String,
			bytes_up     UInt64,
			bytes_down   UInt64,
			packets_up   UInt64,
			packets_down UInt64,
			connections  UInt32
		) ENGINE = SummingMergeTree((bytes_up, bytes_down, packets_up, packets_down, connections))
		PARTITION BY toYYYYMMDD(minute)
		ORDER BY (peer_id, minute, proto, dst_ip, dst_port, domain, node_id)
		TTL minute + INTERVAL %d DAY`, r.FlowsDays),
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS dns_queries (
			at         DateTime64(3, 'UTC'),
			cluster_id UUID,
			node_id    UUID,
			peer_id    UUID,
			name       String,
			type       LowCardinality(String),
			rcode      LowCardinality(String),
			answers    Array(IPv6)
		) ENGINE = MergeTree
		PARTITION BY toYYYYMMDD(at)
		ORDER BY (peer_id, at)
		TTL toDateTime(at) + INTERVAL %d DAY`, r.DNSDays),
	}
}

type Repo struct {
	ch *ClickHouse
}

// NewRepo создаёт репозиторий и применяет схему
func NewRepo(ctx context.Context, ch *ClickHouse, r Retention) (*Repo, error) {
	var err error
	// ClickHouse стартует дольше fleetd
	for attempt := 0; attempt < 30; attempt++ {
		if err = applySchema(ctx, ch, r); err == nil {
			return &Repo{ch: ch}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return nil, fmt.Errorf("схема ClickHouse: %w", err)
}

// applySchema создаёт таблицы
func applySchema(ctx context.Context, ch *ClickHouse, r Retention) error {
	for _, ddl := range schema(r) {
		if err := ch.Exec(ctx, ddl); err != nil {
			return err
		}
	}
	return nil
}

// chTime форматирует время для DateTime в UTC
func chTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05")
}

// chIP приводит адрес к формату колонки IPv6
func chIP(a netip.Addr) string {
	if !a.IsValid() {
		return "::"
	}
	return netip.AddrFrom16(a.As16()).String()
}

// isServicePeer отсекает служебных пиров проб
func isServicePeer(id string) bool {
	return id == "" || strings.HasPrefix(id, "probe:")
}

type usageRow struct {
	TS        string `json:"ts"`
	ClusterID string `json:"cluster_id"`
	NodeID    string `json:"node_id"`
	PeerID    string `json:"peer_id"`
	Rx        uint64 `json:"rx"`
	Tx        uint64 `json:"tx"`
}

type flowRow struct {
	Minute      string `json:"minute"`
	ClusterID   string `json:"cluster_id"`
	NodeID      string `json:"node_id"`
	PeerID      string `json:"peer_id"`
	Proto       uint8  `json:"proto"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Domain      string `json:"domain"`
	BytesUp     uint64 `json:"bytes_up"`
	BytesDown   uint64 `json:"bytes_down"`
	PacketsUp   uint64 `json:"packets_up"`
	PacketsDown uint64 `json:"packets_down"`
	Connections uint32 `json:"connections"`
}

type dnsRow struct {
	At        string   `json:"at"`
	ClusterID string   `json:"cluster_id"`
	NodeID    string   `json:"node_id"`
	PeerID    string   `json:"peer_id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	RCode     string   `json:"rcode"`
	Answers   []string `json:"answers"`
}

// WriteReport сохраняет телеметрию из отчёта агента
func (r *Repo) WriteReport(ctx context.Context, clusterID, nodeID string, rep agentapi.Report) error {
	usage := make([]usageRow, 0, len(rep.Usage))
	for _, u := range rep.Usage {
		if isServicePeer(u.PeerID) || (u.Rx == 0 && u.Tx == 0) {
			continue
		}
		usage = append(usage, usageRow{
			TS: chTime(u.To.Truncate(time.Minute)), ClusterID: clusterID, NodeID: nodeID,
			PeerID: u.PeerID, Rx: u.Rx, Tx: u.Tx,
		})
	}
	flows := make([]flowRow, 0, len(rep.Flows))
	for _, f := range rep.Flows {
		if isServicePeer(f.PeerID) {
			continue
		}
		flows = append(flows, flowRow{
			Minute: chTime(f.Minute), ClusterID: clusterID, NodeID: nodeID, PeerID: f.PeerID,
			Proto: f.Proto, DstIP: chIP(f.DstIP), DstPort: f.DstPort, Domain: f.Domain,
			BytesUp: f.BytesUp, BytesDown: f.BytesDown, PacketsUp: f.PacketsUp, PacketsDown: f.PacketsDown,
			Connections: f.Connections,
		})
	}
	queries := make([]dnsRow, 0, len(rep.DNSQueries))
	for _, q := range rep.DNSQueries {
		if isServicePeer(q.PeerID) {
			continue
		}
		answers := make([]string, len(q.Answers))
		for i, a := range q.Answers {
			answers[i] = chIP(a)
		}
		queries = append(queries, dnsRow{
			At: q.At.UTC().Format("2006-01-02 15:04:05.000"), ClusterID: clusterID, NodeID: nodeID,
			PeerID: q.PeerID, Name: q.Name, Type: q.Type, RCode: q.RCode, Answers: answers,
		})
	}
	if err := Insert(ctx, r.ch, "peer_usage", usage); err != nil {
		return fmt.Errorf("peer_usage: %w", err)
	}
	if err := Insert(ctx, r.ch, "flows", flows); err != nil {
		return fmt.Errorf("flows: %w", err)
	}
	if err := Insert(ctx, r.ch, "dns_queries", queries); err != nil {
		return fmt.Errorf("dns_queries: %w", err)
	}
	return nil
}

type PeerTotal struct {
	PeerID string `json:"peer_id"`
	Rx     uint64 `json:"rx"`
	Tx     uint64 `json:"tx"`
}

// UsageTotals возвращает суммарный трафик всех пиров за период
func (r *Repo) UsageTotals(ctx context.Context, from, to time.Time) ([]PeerTotal, error) {
	return Select[PeerTotal](ctx, r.ch, `SELECT toString(peer_id) AS peer_id, sum(rx) AS rx, sum(tx) AS tx
		FROM peer_usage WHERE peer_usage.ts >= {from:DateTime} AND peer_usage.ts < {to:DateTime}
		GROUP BY peer_id ORDER BY rx + tx DESC`,
		map[string]string{"from": chTime(from), "to": chTime(to)})
}

type UsagePoint struct {
	TS string `json:"ts"`
	Rx uint64 `json:"rx"`
	Tx uint64 `json:"tx"`
}

// UsageSeries возвращает трафик пира с шагом step секунд
func (r *Repo) UsageSeries(ctx context.Context, peerIDs []string, from, to time.Time, step int) ([]UsagePoint, error) {
	return Select[UsagePoint](ctx, r.ch, `SELECT formatDateTime(toStartOfInterval(ts, toIntervalSecond({step:UInt32})), '%FT%TZ') AS ts,
			sum(rx) AS rx, sum(tx) AS tx
		FROM peer_usage
		WHERE peer_usage.peer_id IN {peers:Array(UUID)} AND peer_usage.ts >= {from:DateTime} AND peer_usage.ts < {to:DateTime}
		GROUP BY ts ORDER BY ts`,
		map[string]string{"peers": chArray(peerIDs), "from": chTime(from), "to": chTime(to), "step": strconv.Itoa(step)})
}

type Destination struct {
	Domain      string `json:"domain"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Proto       uint8  `json:"proto"`
	BytesUp     uint64 `json:"bytes_up"`
	BytesDown   uint64 `json:"bytes_down"`
	Connections uint64 `json:"connections"`
}

// TopDestinations возвращает самые «тяжёлые» назначения пиров
func (r *Repo) TopDestinations(ctx context.Context, peerIDs []string, from, to time.Time, groupByDomain bool, limit int) ([]Destination, error) {
	query := `SELECT domain, replaceOne(toString(dst_ip), '::ffff:', '') AS dst_ip, dst_port, proto,
			sum(bytes_up) AS bytes_up, sum(bytes_down) AS bytes_down, sum(connections) AS connections
		FROM flows
		WHERE flows.peer_id IN {peers:Array(UUID)} AND flows.minute >= {from:DateTime} AND flows.minute < {to:DateTime}
		GROUP BY domain, dst_ip, dst_port, proto`
	if groupByDomain {
		query = `SELECT if(domain = '', replaceOne(toString(dst_ip), '::ffff:', ''), domain) AS domain, '' AS dst_ip, 0 AS dst_port, 0 AS proto,
				sum(bytes_up) AS bytes_up, sum(bytes_down) AS bytes_down, sum(connections) AS connections
			FROM flows
			WHERE flows.peer_id IN {peers:Array(UUID)} AND flows.minute >= {from:DateTime} AND flows.minute < {to:DateTime}
			GROUP BY domain`
	}
	query += ` ORDER BY bytes_up + bytes_down DESC LIMIT {limit:UInt32}`
	return Select[Destination](ctx, r.ch, query, map[string]string{
		"peers": chArray(peerIDs), "from": chTime(from), "to": chTime(to), "limit": strconv.Itoa(limit),
	})
}

type DNSLogEntry struct {
	At      string   `json:"at"`
	PeerID  string   `json:"peer_id"`
	Name    string   `json:"name"`
	Type    string   `json:"type"`
	RCode   string   `json:"rcode"`
	Answers []string `json:"answers"`
}

// DNSLog возвращает последние DNS-запросы пиров
func (r *Repo) DNSLog(ctx context.Context, peerIDs []string, from, to time.Time, limit int) ([]DNSLogEntry, error) {
	return Select[DNSLogEntry](ctx, r.ch, `SELECT formatDateTime(at, '%FT%TZ') AS at, toString(peer_id) AS peer_id, name, type, rcode,
			arrayMap(x -> replaceOne(toString(x), '::ffff:', ''), answers) AS answers
		FROM dns_queries
		WHERE dns_queries.peer_id IN {peers:Array(UUID)} AND dns_queries.at >= {from:DateTime} AND dns_queries.at < {to:DateTime}
		ORDER BY dns_queries.at DESC LIMIT {limit:UInt32}`,
		map[string]string{"peers": chArray(peerIDs), "from": chTime(from), "to": chTime(to), "limit": strconv.Itoa(limit)})
}

// chArray форматирует литерал массива ClickHouse
func chArray(items []string) string {
	quoted := make([]string, len(items))
	for i, s := range items {
		quoted[i] = "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
	}
	return "[" + strings.Join(quoted, ",") + "]"
}
