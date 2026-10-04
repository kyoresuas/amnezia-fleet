package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

const userColumns = `id, name, note, status, traffic_limit_bytes, expires_at, device_limit, link_token_hash IS NOT NULL, created_at`

// scanUser читает пользователя
func scanUser(row pgx.Row) (model.User, error) {
	var u model.User
	var status string
	err := row.Scan(&u.ID, &u.Name, &u.Note, &status, &u.TrafficLimitBytes, &u.ExpiresAt, &u.DeviceLimit, &u.HasLink, &u.CreatedAt)
	u.Status = model.UserStatus(status)
	return u, mapErr(err)
}

// CreateUser создаёт пользователя
func (s *Store) CreateUser(ctx context.Context, u model.User) (model.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `INSERT INTO users (name, note, traffic_limit_bytes, expires_at, device_limit)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+userColumns, u.Name, u.Note, u.TrafficLimitBytes, u.ExpiresAt, u.DeviceLimit))
}

// GetUser возвращает пользователя
func (s *Store) GetUser(ctx context.Context, id string) (model.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// ListUsers возвращает всех пользователей
func (s *Store) ListUsers(ctx context.Context) ([]model.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userColumns+` FROM users ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (model.User, error) { return scanUser(r) })
}

type UserPatch struct {
	Name   *string
	Note   *string
	Status *model.UserStatus
	// nil внутри снимает значение
	TrafficLimitBytes **int64
	ExpiresAt         **time.Time
	DeviceLimit       **int
}

// UpdateUser применяет патч и поднимает ревизии затронутых кластеров
func (s *Store) UpdateUser(ctx context.Context, id string, p UserPatch) (model.User, error) {
	var out model.User
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1 FOR UPDATE`, id))
		if err != nil {
			return err
		}
		if p.Name != nil {
			cur.Name = *p.Name
		}
		if p.Note != nil {
			cur.Note = *p.Note
		}
		if p.Status != nil {
			cur.Status = *p.Status
		}
		if p.TrafficLimitBytes != nil {
			cur.TrafficLimitBytes = *p.TrafficLimitBytes
		}
		if p.ExpiresAt != nil {
			cur.ExpiresAt = *p.ExpiresAt
		}
		if p.DeviceLimit != nil {
			cur.DeviceLimit = *p.DeviceLimit
		}
		out, err = scanUser(tx.QueryRow(ctx, `UPDATE users SET name = $2, note = $3, status = $4,
			traffic_limit_bytes = $5, expires_at = $6, device_limit = $7 WHERE id = $1 RETURNING `+userColumns,
			id, cur.Name, cur.Note, string(cur.Status), cur.TrafficLimitBytes, cur.ExpiresAt, cur.DeviceLimit))
		if err != nil {
			return err
		}
		return bumpUserClusters(ctx, tx, id)
	})
	return out, mapErr(err)
}

// bumpUserClusters поднимает ревизии кластеров пользователя
func bumpUserClusters(ctx context.Context, q querier, userID string) error {
	_, err := q.Exec(ctx, `UPDATE clusters SET revision = revision + 1, updated_at = now()
		WHERE id IN (SELECT DISTINCT cluster_id FROM peers WHERE user_id = $1)`, userID)
	return err
}

// DeleteUser удаляет пользователя вместе с пирами
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := bumpUserClusters(ctx, tx, id); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SuspendUser переводит пользователя в suspended, если он ещё активен
func (s *Store) SuspendUser(ctx context.Context, id string) (bool, error) {
	var changed bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET status = 'suspended' WHERE id = $1 AND status = 'active'`, id)
		if err != nil {
			return err
		}
		changed = tag.RowsAffected() > 0
		if !changed {
			return nil
		}
		return bumpUserClusters(ctx, tx, id)
	})
	return changed, err
}

// BumpExpiredUsers поднимает ревизии кластеров истёкших пользователей
func (s *Store) BumpExpiredUsers(ctx context.Context, since time.Time) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE clusters SET revision = revision + 1, updated_at = now()
		WHERE id IN (SELECT DISTINCT p.cluster_id FROM peers p JOIN users u ON u.id = p.user_id
			WHERE u.expires_at > $1 AND u.expires_at <= now())`, since)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// SetUserLink сохраняет новый токен ссылки для устройств, старая ссылка перестаёт работать
func (s *Store) SetUserLink(ctx context.Context, id, token string, hash []byte) error {
	sealed, err := s.box.Seal([]byte(token))
	if err != nil {
		return err
	}
	tag, err := s.pool.Exec(ctx, `UPDATE users SET link_token_enc = $2, link_token_hash = $3 WHERE id = $1`, id, sealed, hash)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UserLink возвращает токен ссылки пользователя или пустую строку
func (s *Store) UserLink(ctx context.Context, id string) (string, error) {
	var sealed []byte
	if err := s.pool.QueryRow(ctx, `SELECT link_token_enc FROM users WHERE id = $1`, id).Scan(&sealed); err != nil {
		return "", mapErr(err)
	}
	if len(sealed) == 0 {
		return "", nil
	}
	raw, err := s.box.Open(sealed)
	return string(raw), err
}

// DeleteUserLink отключает ссылку для устройств
func (s *Store) DeleteUserLink(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE users SET link_token_enc = NULL, link_token_hash = NULL WHERE id = $1`, id)
	return err
}

// GetUserByLink находит пользователя по хешу токена ссылки
func (s *Store) GetUserByLink(ctx context.Context, hash []byte) (model.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE link_token_hash = $1`, hash))
}
