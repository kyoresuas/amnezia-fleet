package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

// sealKey шифрует ключ для хранения
func (s *Store) sealKey(k awg.Key) ([]byte, error) {
	if k.IsZero() {
		return nil, nil
	}
	return s.box.Seal(k[:])
}

// openKey расшифровывает ключ
func (s *Store) openKey(sealed []byte) (awg.Key, error) {
	if len(sealed) == 0 {
		return awg.Key{}, nil
	}
	raw, err := s.box.Open(sealed)
	if err != nil {
		return awg.Key{}, fmt.Errorf("расшифровка ключа: %w", err)
	}
	var k awg.Key
	if len(raw) != len(k) {
		return awg.Key{}, fmt.Errorf("неверная длина расшифрованного ключа")
	}
	copy(k[:], raw)
	return k, nil
}

const clusterColumns = `id, name, hostname, listen_port, public_key, private_key_enc, params,
	subnet_v4, subnet_v6, dns, mtu, dns_mode, dns_ttl, revision, created_at, updated_at`

// scanCluster читает кластер из строки результата и расшифровывает ключ
func (s *Store) scanCluster(row pgx.Row) (model.Cluster, error) {
	var (
		c          model.Cluster
		pub        string
		privSealed []byte
		params     []byte
		subnet6    *netip.Prefix
		dnsMode    string
	)
	err := row.Scan(&c.ID, &c.Name, &c.Hostname, &c.ListenPort, &pub, &privSealed, &params,
		&c.SubnetV4, &subnet6, &c.DNS, &c.MTU, &dnsMode, &c.DNSTTL, &c.Revision, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return model.Cluster{}, mapErr(err)
	}
	c.DNSMode = model.DNSMode(dnsMode)
	if subnet6 != nil {
		c.SubnetV6 = *subnet6
	}
	if c.PublicKey, err = awg.ParseKey(pub); err != nil {
		return model.Cluster{}, err
	}
	if c.PrivateKey, err = s.openKey(privSealed); err != nil {
		return model.Cluster{}, err
	}
	if err := json.Unmarshal(params, &c.Params); err != nil {
		return model.Cluster{}, fmt.Errorf("разбор params кластера: %w", err)
	}
	return c, nil
}

// nullablePrefix превращает пустой префикс в NULL
func nullablePrefix(p netip.Prefix) any {
	if !p.IsValid() {
		return nil
	}
	return p
}

// CreateCluster сохраняет новый кластер
func (s *Store) CreateCluster(ctx context.Context, c model.Cluster) (model.Cluster, error) {
	privSealed, err := s.sealKey(c.PrivateKey)
	if err != nil {
		return model.Cluster{}, err
	}
	params, err := json.Marshal(c.Params)
	if err != nil {
		return model.Cluster{}, err
	}
	row := s.pool.QueryRow(ctx, `INSERT INTO clusters
		(name, hostname, listen_port, public_key, private_key_enc, params, subnet_v4, subnet_v6, dns, mtu, dns_mode, dns_ttl)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING `+clusterColumns,
		c.Name, c.Hostname, c.ListenPort, c.PublicKey.String(), privSealed, params,
		c.SubnetV4, nullablePrefix(c.SubnetV6), c.DNS, c.MTU, string(c.DNSMode), c.DNSTTL)
	return s.scanCluster(row)
}

// GetCluster возвращает кластер по идентификатору
func (s *Store) GetCluster(ctx context.Context, id string) (model.Cluster, error) {
	return s.scanCluster(s.pool.QueryRow(ctx, `SELECT `+clusterColumns+` FROM clusters WHERE id = $1`, id))
}

// ListClusters возвращает все кластеры
func (s *Store) ListClusters(ctx context.Context) ([]model.Cluster, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+clusterColumns+` FROM clusters ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Cluster
	for rows.Next() {
		c, err := s.scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

type ClusterPatch struct {
	Hostname     *string
	DNS          []string
	MTU          *int
	DNSMode      *model.DNSMode
	DNSTTL       *int
	ClientParams *awg.Params
}

// UpdateCluster применяет патч и поднимает ревизию
func (s *Store) UpdateCluster(ctx context.Context, id string, p ClusterPatch) (model.Cluster, error) {
	var out model.Cluster
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := s.scanCluster(tx.QueryRow(ctx, `SELECT `+clusterColumns+` FROM clusters WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if p.Hostname != nil {
			cur.Hostname = *p.Hostname
		}
		if p.DNS != nil {
			cur.DNS = p.DNS
		}
		if p.MTU != nil {
			cur.MTU = *p.MTU
		}
		if p.DNSMode != nil {
			cur.DNSMode = *p.DNSMode
		}
		if p.DNSTTL != nil {
			cur.DNSTTL = *p.DNSTTL
		}
		if p.ClientParams != nil {
			cur.Params = mergeClientParams(cur.Params, *p.ClientParams)
			if err := cur.Params.Validate(); err != nil {
				return err
			}
		}
		params, err := json.Marshal(cur.Params)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE clusters SET hostname = $2, dns = $3, mtu = $4, dns_mode = $5, dns_ttl = $6,
			params = $7, revision = revision + 1, updated_at = now() WHERE id = $1`,
			id, cur.Hostname, cur.DNS, cur.MTU, string(cur.DNSMode), cur.DNSTTL, params)
		if err != nil {
			return err
		}
		out, err = s.scanCluster(tx.QueryRow(ctx, `SELECT `+clusterColumns+` FROM clusters WHERE id = $1`, id))
		return err
	})
	return out, mapErr(err)
}

// mergeClientParams переносит в текущий профиль только параметры, которые
func mergeClientParams(cur, next awg.Params) awg.Params {
	cur.Jc, cur.Jmin, cur.Jmax = next.Jc, next.Jmin, next.Jmax
	cur.I1, cur.I2, cur.I3, cur.I4, cur.I5 = next.I1, next.I2, next.I3, next.I4, next.I5
	cur.ContentPaddingAddition = next.ContentPaddingAddition
	cur.RekeyAfterTime = next.RekeyAfterTime
	cur.RekeyTimeout = next.RekeyTimeout
	cur.RejectAfterTime = next.RejectAfterTime
	cur.KeepaliveTimeout = next.KeepaliveTimeout
	cur.MaxHandshakeAttempts = next.MaxHandshakeAttempts
	cur.PersistentKeepalive = next.PersistentKeepalive
	cur.DisableCookies = next.DisableCookies
	return cur
}

// DeleteCluster удаляет кластер вместе с узлами и пирами
func (s *Store) DeleteCluster(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM clusters WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClusterRevision возвращает только ревизию кластера
func (s *Store) ClusterRevision(ctx context.Context, id string) (int64, error) {
	var rev int64
	err := s.pool.QueryRow(ctx, `SELECT revision FROM clusters WHERE id = $1`, id).Scan(&rev)
	return rev, mapErr(err)
}
