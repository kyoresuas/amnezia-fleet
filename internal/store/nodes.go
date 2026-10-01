package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

const nodeColumns = `id, cluster_id, name, state, last_seen_at, agent_version, applied_revision, last_error, created_at`

const addressColumns = `id, node_id, ip, state, priority, health, health_changed_at, created_at`

// scanNode читает узел без адресов
func scanNode(row pgx.Row) (model.Node, error) {
	var n model.Node
	var state string
	err := row.Scan(&n.ID, &n.ClusterID, &n.Name, &state, &n.LastSeenAt, &n.AgentVersion,
		&n.AppliedRevision, &n.LastError, &n.CreatedAt)
	n.State = model.NodeState(state)
	return n, mapErr(err)
}

// scanAddress читает адрес узла
func scanAddress(row pgx.Row) (model.Address, error) {
	var a model.Address
	var ip netip.Prefix
	var state string
	err := row.Scan(&a.ID, &a.NodeID, &ip, &state, &a.Priority, &a.Health, &a.HealthChangedAt, &a.CreatedAt)
	a.IP = ip.Addr()
	a.State = model.AddressState(state)
	return a, mapErr(err)
}

// CreateNode регистрирует узел с адресами
func (s *Store) CreateNode(ctx context.Context, clusterID, name string, tokenHash []byte, ips []netip.Addr) (model.Node, error) {
	var out model.Node
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		n, err := scanNode(tx.QueryRow(ctx, `INSERT INTO nodes (cluster_id, name, agent_token_hash)
			VALUES ($1, $2, $3) RETURNING `+nodeColumns, clusterID, name, tokenHash))
		if err != nil {
			return err
		}
		for i, ip := range ips {
			// первый адрес активный, остальные запасные
			state := model.AddressActive
			if i > 0 {
				state = model.AddressSpare
			}
			a, err := scanAddress(tx.QueryRow(ctx, `INSERT INTO node_addresses (node_id, ip, state, priority)
				VALUES ($1, $2, $3, $4) RETURNING `+addressColumns, n.ID, ip.String(), string(state), 100+i))
			if err != nil {
				return err
			}
			n.Addresses = append(n.Addresses, a)
		}
		out = n
		return bumpRevision(ctx, tx, clusterID)
	})
	return out, mapErr(err)
}

// GetNode возвращает узел с адресами
func (s *Store) GetNode(ctx context.Context, id string) (model.Node, error) {
	n, err := scanNode(s.pool.QueryRow(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE id = $1`, id))
	if err != nil {
		return model.Node{}, err
	}
	n.Addresses, err = s.listAddresses(ctx, `WHERE node_id = $1`, id)
	return n, err
}

// GetNodeByTokenHash находит узел по хешу токена агента
func (s *Store) GetNodeByTokenHash(ctx context.Context, hash []byte) (model.Node, error) {
	n, err := scanNode(s.pool.QueryRow(ctx, `SELECT `+nodeColumns+` FROM nodes WHERE agent_token_hash = $1`, hash))
	if err != nil {
		return model.Node{}, err
	}
	n.Addresses, err = s.listAddresses(ctx, `WHERE node_id = $1`, n.ID)
	return n, err
}

// ListNodes возвращает узлы кластера с адресами
func (s *Store) ListNodes(ctx context.Context, clusterID string) ([]model.Node, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+nodeColumns+` FROM nodes
		WHERE ($1 = '' OR cluster_id::text = $1) ORDER BY name`, clusterID)
	if err != nil {
		return nil, err
	}
	nodes, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (model.Node, error) { return scanNode(r) })
	if err != nil {
		return nil, err
	}
	addrs, err := s.listAddresses(ctx, `WHERE node_id IN (SELECT id FROM nodes WHERE ($1 = '' OR cluster_id::text = $1))`, clusterID)
	if err != nil {
		return nil, err
	}
	byNode := map[string][]model.Address{}
	for _, a := range addrs {
		byNode[a.NodeID] = append(byNode[a.NodeID], a)
	}
	for i := range nodes {
		nodes[i].Addresses = byNode[nodes[i].ID]
	}
	return nodes, nil
}

// listAddresses выбирает адреса по условию, упорядочивая по приоритету
func (s *Store) listAddresses(ctx context.Context, where string, args ...any) ([]model.Address, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+addressColumns+` FROM node_addresses `+where+` ORDER BY priority, ip`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (model.Address, error) { return scanAddress(r) })
}

// ListAllAddresses возвращает все адреса всех узлов
func (s *Store) ListAllAddresses(ctx context.Context) ([]model.Address, error) {
	return s.listAddresses(ctx, ``)
}

// SetNodeState меняет административное состояние узла
func (s *Store) SetNodeState(ctx context.Context, id string, state model.NodeState) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var clusterID string
		err := tx.QueryRow(ctx, `UPDATE nodes SET state = $2 WHERE id = $1 RETURNING cluster_id`, id, string(state)).Scan(&clusterID)
		if err != nil {
			return mapErr(err)
		}
		return bumpRevision(ctx, tx, clusterID)
	})
}

// RotateNodeToken заменяет хеш токена агента
func (s *Store) RotateNodeToken(ctx context.Context, id string, tokenHash []byte) error {
	tag, err := s.pool.Exec(ctx, `UPDATE nodes SET agent_token_hash = $2 WHERE id = $1`, id, tokenHash)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteNode удаляет узел
func (s *Store) DeleteNode(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var clusterID string
		if err := tx.QueryRow(ctx, `DELETE FROM nodes WHERE id = $1 RETURNING cluster_id`, id).Scan(&clusterID); err != nil {
			return mapErr(err)
		}
		return bumpRevision(ctx, tx, clusterID)
	})
}

type NodeReport struct {
	AgentVersion    string
	AppliedRevision int64
	LastError       string
}

// TouchNode фиксирует heartbeat агента
func (s *Store) TouchNode(ctx context.Context, id string, r NodeReport) error {
	_, err := s.pool.Exec(ctx, `UPDATE nodes SET last_seen_at = now(), agent_version = $2,
		applied_revision = $3, last_error = $4 WHERE id = $1`, id, r.AgentVersion, r.AppliedRevision, r.LastError)
	return err
}

// AddAddress добавляет узлу публичный адрес
func (s *Store) AddAddress(ctx context.Context, nodeID string, ip netip.Addr, state model.AddressState, priority int) (model.Address, error) {
	return scanAddress(s.pool.QueryRow(ctx, `INSERT INTO node_addresses (node_id, ip, state, priority)
		VALUES ($1, $2, $3, $4) RETURNING `+addressColumns, nodeID, ip.String(), string(state), priority))
}

type AddressPatch struct {
	State    *model.AddressState
	Priority *int
}

// UpdateAddress меняет состояние или приоритет адреса
func (s *Store) UpdateAddress(ctx context.Context, id string, p AddressPatch) (model.Address, error) {
	var state, priority any
	if p.State != nil {
		state = string(*p.State)
	}
	if p.Priority != nil {
		priority = *p.Priority
	}
	return scanAddress(s.pool.QueryRow(ctx, `UPDATE node_addresses SET
		state = COALESCE($2::text, state), priority = COALESCE($3::integer, priority)
		WHERE id = $1 RETURNING `+addressColumns, id, state, priority))
}

// DeleteAddress удаляет адрес
func (s *Store) DeleteAddress(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM node_addresses WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetAddressHealth сохраняет здоровье адреса
func (s *Store) SetAddressHealth(ctx context.Context, id, health string) (changed bool, err error) {
	tag, err := s.pool.Exec(ctx, `UPDATE node_addresses SET health = $2, health_changed_at = $3
		WHERE id = $1 AND health <> $2`, id, health, time.Now())
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
