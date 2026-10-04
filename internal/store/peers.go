package store

import (
	"context"
	"errors"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/ipam"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

const peerColumns = `p.id, p.user_id, p.cluster_id, p.name, p.public_key, p.private_key_enc, p.preshared_key_enc,
	p.address_v4, p.address_v6, p.enabled, p.created_at`

// scanPeer читает пира и расшифровывает его ключи
func (s *Store) scanPeer(row pgx.Row) (model.Peer, error) {
	var (
		p                  model.Peer
		pub                string
		privSealed, pskEnc []byte
		addr4              netip.Prefix
		addr6              *netip.Prefix
	)
	err := row.Scan(&p.ID, &p.UserID, &p.ClusterID, &p.Name, &pub, &privSealed, &pskEnc,
		&addr4, &addr6, &p.Enabled, &p.CreatedAt)
	if err != nil {
		return model.Peer{}, mapErr(err)
	}
	p.AddressV4 = addr4.Addr()
	if addr6 != nil {
		p.AddressV6 = addr6.Addr()
	}
	if p.PublicKey, err = awg.ParseKey(pub); err != nil {
		return model.Peer{}, err
	}
	if p.PrivateKey, err = s.openKey(privSealed); err != nil {
		return model.Peer{}, err
	}
	if p.PresharedKey, err = s.openKey(pskEnc); err != nil {
		return model.Peer{}, err
	}
	return p, nil
}

// collectPeers читает все строки результата в слайс пиров
func (s *Store) collectPeers(rows pgx.Rows, err error) ([]model.Peer, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Peer
	for rows.Next() {
		p, err := s.scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ErrDeviceLimit возвращается, когда у пользователя кончился лимит устройств
var ErrDeviceLimit = errors.New("достигнут лимит устройств")

// CreatePeer сохраняет пира, выделяя ему свободный адрес в подсети кластера
func (s *Store) CreatePeer(ctx context.Context, p model.Peer, enforceLimit bool) (model.Peer, error) {
	var out model.Peer
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if enforceLimit {
			var limit *int
			if err := tx.QueryRow(ctx, `SELECT device_limit FROM users WHERE id = $1 FOR UPDATE`, p.UserID).Scan(&limit); err != nil {
				return mapErr(err)
			}
			if limit != nil {
				var n int
				if err := tx.QueryRow(ctx, `SELECT count(*) FROM peers WHERE user_id = $1`, p.UserID).Scan(&n); err != nil {
					return err
				}
				if n >= *limit {
					return ErrDeviceLimit
				}
			}
		}
		var subnet4 netip.Prefix
		var subnet6 *netip.Prefix
		if err := tx.QueryRow(ctx, `SELECT subnet_v4, subnet_v6 FROM clusters WHERE id = $1 FOR UPDATE`, p.ClusterID).
			Scan(&subnet4, &subnet6); err != nil {
			return mapErr(err)
		}
		rows, err := tx.Query(ctx, `SELECT address_v4 FROM peers WHERE cluster_id = $1`, p.ClusterID)
		if err != nil {
			return err
		}
		usedList, err := pgx.CollectRows(rows, pgx.RowTo[netip.Prefix])
		if err != nil {
			return err
		}
		used := make(map[netip.Addr]bool, len(usedList))
		for _, u := range usedList {
			used[u.Addr()] = true
		}
		if p.AddressV4, err = ipam.NextFreeV4(subnet4, used); err != nil {
			return err
		}
		var addr6 any
		if subnet6 != nil {
			if p.AddressV6, err = ipam.MapToV6(subnet4, p.AddressV4, *subnet6); err != nil {
				return err
			}
			addr6 = p.AddressV6.String()
		}
		privSealed, err := s.sealKey(p.PrivateKey)
		if err != nil {
			return err
		}
		pskSealed, err := s.sealKey(p.PresharedKey)
		if err != nil {
			return err
		}
		var id string
		err = tx.QueryRow(ctx, `INSERT INTO peers
			(user_id, cluster_id, name, public_key, private_key_enc, preshared_key_enc, address_v4, address_v6)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
			p.UserID, p.ClusterID, p.Name, p.PublicKey.String(), privSealed, pskSealed, p.AddressV4.String(), addr6).Scan(&id)
		if err != nil {
			return mapErr(err)
		}
		if out, err = s.scanPeer(tx.QueryRow(ctx, `SELECT `+peerColumns+` FROM peers p WHERE p.id = $1`, id)); err != nil {
			return err
		}
		return bumpRevision(ctx, tx, p.ClusterID)
	})
	return out, mapErr(err)
}

// GetPeer возвращает пира
func (s *Store) GetPeer(ctx context.Context, id string) (model.Peer, error) {
	return s.scanPeer(s.pool.QueryRow(ctx, `SELECT `+peerColumns+` FROM peers p WHERE p.id = $1`, id))
}

type PeerFilter struct {
	UserID    string
	ClusterID string
}

// ListPeers возвращает пиров по фильтру
func (s *Store) ListPeers(ctx context.Context, f PeerFilter) ([]model.Peer, error) {
	return s.collectPeers(s.pool.Query(ctx, `SELECT `+peerColumns+` FROM peers p
		WHERE ($1 = '' OR p.user_id::text = $1) AND ($2 = '' OR p.cluster_id::text = $2)
		ORDER BY p.created_at`, f.UserID, f.ClusterID))
}

// ListActivePeers возвращает пиров, которые должны быть на узлах кластера
func (s *Store) ListActivePeers(ctx context.Context, clusterID string) ([]model.Peer, error) {
	return s.collectPeers(s.pool.Query(ctx, `SELECT `+peerColumns+` FROM peers p
		JOIN users u ON u.id = p.user_id
		WHERE p.cluster_id = $1 AND p.enabled AND u.status = 'active'
			AND (u.expires_at IS NULL OR u.expires_at > now())
		ORDER BY p.address_v4`, clusterID))
}

// SetPeerEnabled включает или отключает пира
func (s *Store) SetPeerEnabled(ctx context.Context, id string, enabled bool) (model.Peer, error) {
	var out model.Peer
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var clusterID string
		if err := tx.QueryRow(ctx, `UPDATE peers SET enabled = $2 WHERE id = $1 RETURNING cluster_id`, id, enabled).
			Scan(&clusterID); err != nil {
			return mapErr(err)
		}
		var err error
		if out, err = s.scanPeer(tx.QueryRow(ctx, `SELECT `+peerColumns+` FROM peers p WHERE p.id = $1`, id)); err != nil {
			return err
		}
		return bumpRevision(ctx, tx, clusterID)
	})
	return out, mapErr(err)
}

// DeletePeer удаляет пира
func (s *Store) DeletePeer(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var clusterID string
		if err := tx.QueryRow(ctx, `DELETE FROM peers WHERE id = $1 RETURNING cluster_id`, id).Scan(&clusterID); err != nil {
			return mapErr(err)
		}
		return bumpRevision(ctx, tx, clusterID)
	})
}
