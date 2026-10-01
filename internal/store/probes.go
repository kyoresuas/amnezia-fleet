package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

const probeColumns = `id, name, region, public_key, last_seen_at, created_at`

// scanProbe читает наблюдателя
func scanProbe(row pgx.Row) (model.Probe, error) {
	var p model.Probe
	var pub string
	if err := row.Scan(&p.ID, &p.Name, &p.Region, &pub, &p.LastSeenAt, &p.CreatedAt); err != nil {
		return model.Probe{}, mapErr(err)
	}
	var err error
	p.PublicKey, err = awg.ParseKey(pub)
	return p, err
}

// CreateProbe регистрирует наблюдателя
func (s *Store) CreateProbe(ctx context.Context, name, region string, pub awg.Key, tokenHash []byte) (model.Probe, error) {
	var out model.Probe
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = scanProbe(tx.QueryRow(ctx, `INSERT INTO probes (name, region, public_key, token_hash)
			VALUES ($1, $2, $3, $4) RETURNING `+probeColumns, name, region, pub.String(), tokenHash))
		if err != nil {
			return err
		}
		return bumpAllRevisions(ctx, tx)
	})
	return out, mapErr(err)
}

// ListProbes возвращает всех наблюдателей
func (s *Store) ListProbes(ctx context.Context) ([]model.Probe, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+probeColumns+` FROM probes ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (model.Probe, error) { return scanProbe(r) })
}

// GetProbeByTokenHash находит пробу по токену
func (s *Store) GetProbeByTokenHash(ctx context.Context, hash []byte) (model.Probe, error) {
	return scanProbe(s.pool.QueryRow(ctx, `UPDATE probes SET last_seen_at = now()
		WHERE token_hash = $1 RETURNING `+probeColumns, hash))
}

// DeleteProbe удаляет наблюдателя и убирает его пира из кластеров
func (s *Store) DeleteProbe(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM probes WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return bumpAllRevisions(ctx, tx)
	})
}

type ProbeTarget struct {
	AddressID       string     `json:"address_id"`
	IP              netip.Addr `json:"ip"`
	Port            uint16     `json:"port"`
	ClusterID       string     `json:"cluster_id"`
	ServerPublicKey awg.Key    `json:"server_public_key"`
	Params          awg.Params `json:"params"`
}

// ListProbeTargets возвращает адреса для проверки
func (s *Store) ListProbeTargets(ctx context.Context) ([]ProbeTarget, error) {
	clusters, err := s.ListClusters(ctx)
	if err != nil {
		return nil, err
	}
	byID := make(map[string]model.Cluster, len(clusters))
	for _, c := range clusters {
		byID[c.ID] = c
	}
	rows, err := s.pool.Query(ctx, `SELECT a.id, a.ip, n.cluster_id FROM node_addresses a
		JOIN nodes n ON n.id = a.node_id
		WHERE a.state <> 'disabled' AND n.state <> 'disabled'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeTarget
	for rows.Next() {
		var t ProbeTarget
		var ip netip.Prefix
		if err := rows.Scan(&t.AddressID, &ip, &t.ClusterID); err != nil {
			return nil, err
		}
		c := byID[t.ClusterID]
		t.IP, t.Port, t.ServerPublicKey, t.Params = ip.Addr(), c.ListenPort, c.PublicKey, c.Params
		out = append(out, t)
	}
	return out, rows.Err()
}

type ProbeResult struct {
	AddressID string `json:"address_id"`
	OK        bool   `json:"ok"`
	RTTMs     *int   `json:"rtt_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}

// RecordProbeResults сохраняет результаты проб
func (s *Store) RecordProbeResults(ctx context.Context, probeID string, results []ProbeResult) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		for _, r := range results {
			// адрес мог быть удалён во время проверки
			_, err := tx.Exec(ctx, `INSERT INTO probe_results (probe_id, address_id, ok, rtt_ms, error)
				SELECT $1, $2::uuid, $3, $4, $5 WHERE EXISTS (SELECT 1 FROM node_addresses WHERE id = $2::uuid)
				ON CONFLICT (probe_id, address_id) DO UPDATE SET
					streak = CASE WHEN probe_results.ok = EXCLUDED.ok THEN probe_results.streak + 1 ELSE 1 END,
					ok = EXCLUDED.ok, rtt_ms = EXCLUDED.rtt_ms, error = EXCLUDED.error, checked_at = now()`,
				probeID, r.AddressID, r.OK, r.RTTMs, r.Error)
			if err != nil {
				return mapErr(err)
			}
		}
		return nil
	})
}

type ProbeStatus struct {
	ProbeID   string    `json:"probe_id"`
	AddressID string    `json:"address_id"`
	OK        bool      `json:"ok"`
	Streak    int       `json:"streak"`
	RTTMs     *int      `json:"rtt_ms,omitempty"`
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

// ListProbeStatuses возвращает результаты не старше maxAge
func (s *Store) ListProbeStatuses(ctx context.Context, maxAge time.Duration) ([]ProbeStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT probe_id, address_id, ok, streak, rtt_ms, error, checked_at
		FROM probe_results WHERE checked_at > now() - make_interval(secs => $1)`, maxAge.Seconds())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ProbeStatus, error) {
		var p ProbeStatus
		err := r.Scan(&p.ProbeID, &p.AddressID, &p.OK, &p.Streak, &p.RTTMs, &p.Error, &p.CheckedAt)
		return p, err
	})
}

type DNSState struct {
	ClusterID string       `json:"cluster_id"`
	Records   []netip.Addr `json:"records"`
	SyncedAt  *time.Time   `json:"synced_at,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// GetDNSState возвращает последнее опубликованное состояние DNS кластера
func (s *Store) GetDNSState(ctx context.Context, clusterID string) (DNSState, error) {
	st := DNSState{ClusterID: clusterID}
	var recs []netip.Prefix
	err := s.pool.QueryRow(ctx, `SELECT records, synced_at, error FROM dns_state WHERE cluster_id = $1`, clusterID).
		Scan(&recs, &st.SyncedAt, &st.Error)
	if err != nil {
		if err == pgx.ErrNoRows {
			return st, nil
		}
		return st, err
	}
	for _, r := range recs {
		st.Records = append(st.Records, r.Addr())
	}
	return st, nil
}

// SaveDNSState сохраняет состояние DNS
func (s *Store) SaveDNSState(ctx context.Context, clusterID string, records []netip.Addr, syncErr string) error {
	if syncErr != "" {
		_, err := s.pool.Exec(ctx, `INSERT INTO dns_state (cluster_id, error) VALUES ($1, $2)
			ON CONFLICT (cluster_id) DO UPDATE SET error = EXCLUDED.error`, clusterID, syncErr)
		return err
	}
	strs := make([]string, len(records))
	for i, r := range records {
		strs[i] = r.String()
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO dns_state (cluster_id, records, synced_at, error) VALUES ($1, $2::inet[], now(), '')
		ON CONFLICT (cluster_id) DO UPDATE SET records = EXCLUDED.records, synced_at = now(), error = ''`, clusterID, strs)
	return err
}
