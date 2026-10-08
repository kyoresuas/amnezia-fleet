package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"

	"github.com/jackc/pgx/v5"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
	"github.com/kyoresuas/amnezia-fleet/internal/ipam"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

const exitColumns = `id, cluster_id, name, endpoint, listen_port, public_key, private_key_enc, params,
	subnet_v4, dns, domains, enabled, last_seen_at, last_error, created_at`

// scanExit читает выход и расшифровывает ключ
func (s *Store) scanExit(row pgx.Row) (model.Exit, error) {
	var (
		e        model.Exit
		endpoint netip.Prefix
		pub      string
		sealed   []byte
		params   []byte
	)
	err := row.Scan(&e.ID, &e.ClusterID, &e.Name, &endpoint, &e.ListenPort, &pub, &sealed, &params,
		&e.SubnetV4, &e.DNS, &e.Domains, &e.Enabled, &e.LastSeenAt, &e.LastError, &e.CreatedAt)
	if err != nil {
		return model.Exit{}, mapErr(err)
	}
	e.Endpoint = endpoint.Addr()
	if e.PublicKey, err = awg.ParseKey(pub); err != nil {
		return model.Exit{}, err
	}
	if e.PrivateKey, err = s.openKey(sealed); err != nil {
		return model.Exit{}, err
	}
	if err := json.Unmarshal(params, &e.Params); err != nil {
		return model.Exit{}, fmt.Errorf("разбор params выхода: %w", err)
	}
	return e, nil
}

// CreateExit сохраняет выход кластера
func (s *Store) CreateExit(ctx context.Context, e model.Exit, tokenHash []byte) (model.Exit, error) {
	sealed, err := s.sealKey(e.PrivateKey)
	if err != nil {
		return model.Exit{}, err
	}
	params, err := json.Marshal(e.Params)
	if err != nil {
		return model.Exit{}, err
	}
	var out model.Exit
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = s.scanExit(tx.QueryRow(ctx, `INSERT INTO exits
			(cluster_id, name, endpoint, listen_port, public_key, private_key_enc, params, subnet_v4, dns, domains, token_hash)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING `+exitColumns,
			e.ClusterID, e.Name, e.Endpoint.String(), e.ListenPort, e.PublicKey.String(), sealed, params,
			e.SubnetV4, e.DNS, e.Domains, tokenHash))
		if err != nil {
			return err
		}
		return bumpRevision(ctx, tx, e.ClusterID)
	})
	return out, mapErr(err)
}

// GetExitByCluster возвращает выход кластера
func (s *Store) GetExitByCluster(ctx context.Context, clusterID string) (model.Exit, error) {
	return s.scanExit(s.pool.QueryRow(ctx, `SELECT `+exitColumns+` FROM exits WHERE cluster_id = $1`, clusterID))
}

// GetExitByTokenHash находит выход по токену и отмечает его активность
func (s *Store) GetExitByTokenHash(ctx context.Context, hash []byte) (model.Exit, error) {
	return s.scanExit(s.pool.QueryRow(ctx, `UPDATE exits SET last_seen_at = now()
		WHERE token_hash = $1 RETURNING `+exitColumns, hash))
}

// ExitPatch, изменяемые поля выхода
type ExitPatch struct {
	Enabled *bool
	Domains []string
	DNS     *string
}

// UpdateExit меняет выход и поднимает ревизию кластера, чтобы узлы забрали изменения
func (s *Store) UpdateExit(ctx context.Context, id string, p ExitPatch) (model.Exit, error) {
	var out model.Exit
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = s.scanExit(tx.QueryRow(ctx, `UPDATE exits SET
			enabled = COALESCE($2, enabled), domains = COALESCE($3, domains), dns = COALESCE($4, dns)
			WHERE id = $1 RETURNING `+exitColumns, id, p.Enabled, p.Domains, p.DNS))
		if err != nil {
			return err
		}
		return bumpRevision(ctx, tx, out.ClusterID)
	})
	return out, mapErr(err)
}

// SetExitError сохраняет последнюю ошибку выхода
func (s *Store) SetExitError(ctx context.Context, id, msg string) error {
	_, err := s.pool.Exec(ctx, `UPDATE exits SET last_error = $2 WHERE id = $1`, id, msg)
	return err
}

// DeleteExit удаляет выход
func (s *Store) DeleteExit(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var clusterID string
		if err := tx.QueryRow(ctx, `DELETE FROM exits WHERE id = $1 RETURNING cluster_id`, id).Scan(&clusterID); err != nil {
			return mapErr(err)
		}
		return bumpRevision(ctx, tx, clusterID)
	})
}

// EnsureExitLink возвращает ключ узла для выхода, создавая его при первом обращении
func (s *Store) EnsureExitLink(ctx context.Context, exitID, nodeID string) (model.ExitLink, error) {
	link := model.ExitLink{ExitID: exitID, NodeID: nodeID}
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var subnet netip.Prefix
		if err := tx.QueryRow(ctx, `SELECT subnet_v4 FROM exits WHERE id = $1 FOR UPDATE`, exitID).Scan(&subnet); err != nil {
			return mapErr(err)
		}
		var pub string
		var sealed []byte
		var addr netip.Prefix
		err := tx.QueryRow(ctx, `SELECT public_key, private_key_enc, address FROM exit_links
			WHERE exit_id = $1 AND node_id = $2`, exitID, nodeID).Scan(&pub, &sealed, &addr)
		if err == nil {
			if link.PublicKey, err = awg.ParseKey(pub); err != nil {
				return err
			}
			link.Address = addr.Addr()
			link.PrivateKey, err = s.openKey(sealed)
			return err
		}
		if err != pgx.ErrNoRows {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT address FROM exit_links WHERE exit_id = $1`, exitID)
		if err != nil {
			return err
		}
		usedList, err := pgx.CollectRows(rows, pgx.RowTo[netip.Prefix])
		if err != nil {
			return err
		}
		used := map[netip.Addr]bool{}
		for _, u := range usedList {
			used[u.Addr()] = true
		}
		if link.Address, err = ipam.NextFreeV4(subnet, used); err != nil {
			return err
		}
		if link.PrivateKey, err = awg.GeneratePrivateKey(); err != nil {
			return err
		}
		link.PublicKey = link.PrivateKey.PublicKey()
		if sealed, err = s.sealKey(link.PrivateKey); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO exit_links (exit_id, node_id, public_key, private_key_enc, address)
			VALUES ($1, $2, $3, $4, $5)`, exitID, nodeID, link.PublicKey.String(), sealed, link.Address.String())
		return err
	})
	return link, mapErr(err)
}

// ListExitLinks возвращает ключи всех узлов выхода
func (s *Store) ListExitLinks(ctx context.Context, exitID string) ([]model.ExitLink, error) {
	rows, err := s.pool.Query(ctx, `SELECT node_id, public_key, address FROM exit_links WHERE exit_id = $1 ORDER BY address`, exitID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (model.ExitLink, error) {
		l := model.ExitLink{ExitID: exitID}
		var pub string
		var addr netip.Prefix
		if err := r.Scan(&l.NodeID, &pub, &addr); err != nil {
			return l, err
		}
		l.Address = addr.Addr()
		var err error
		l.PublicKey, err = awg.ParseKey(pub)
		return l, err
	})
}
