// Package store
package store

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/kyoresuas/amnezia-fleet/internal/secret"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var ErrNotFound = errors.New("не найдено")

var ErrConflict = errors.New("конфликт: запись уже существует")

type Store struct {
	pool *pgxpool.Pool
	box  *secret.Box
}

// Open подключается к базе и применяет миграции
func Open(ctx context.Context, dsn string, box *secret.Box) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("подключение к postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	s := &Store{pool: pool, box: box}
	if err := s.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close закрывает пул соединений
func (s *Store) Close() {
	s.pool.Close()
}

// Ping проверяет доступность базы
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// migrate применяет встроенные миграции
func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		name text PRIMARY KEY,
		applied_at timestamptz NOT NULL DEFAULT now()
	)`); err != nil {
		return fmt.Errorf("создание schema_migrations: %w", err)
	}
	entries, err := fs.ReadDir(migrationsFS, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			// защита от параллельных миграций
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7340211)`); err != nil {
				return err
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE name = $1)`, name).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return nil
			}
			body, err := migrationsFS.ReadFile("migrations/" + name)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, string(body)); err != nil {
				return err
			}
			_, err = tx.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name)
			return err
		})
		if err != nil {
			return fmt.Errorf("миграция %s: %w", name, err)
		}
	}
	return nil
}

// mapErr переводит ошибки драйвера в доменные
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w (%s)", ErrConflict, pgErr.ConstraintName)
	}
	return err
}

type querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// bumpRevision увеличивает ревизию кластера
func bumpRevision(ctx context.Context, q querier, clusterID string) error {
	_, err := q.Exec(ctx, `UPDATE clusters SET revision = revision + 1, updated_at = now() WHERE id = $1`, clusterID)
	return err
}

// bumpAllRevisions увеличивает ревизию всех кластеров
func bumpAllRevisions(ctx context.Context, q querier) error {
	_, err := q.Exec(ctx, `UPDATE clusters SET revision = revision + 1, updated_at = now()`)
	return err
}

// AddEvent пишет событие в журнал
func (s *Store) AddEvent(ctx context.Context, clusterID, nodeID, kind, message string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO events (cluster_id, node_id, kind, message) VALUES (NULLIF($1, '')::uuid, NULLIF($2, '')::uuid, $3, $4)`,
		clusterID, nodeID, kind, message)
	return err
}

type Event struct {
	ID        int64  `json:"id"`
	ClusterID string `json:"cluster_id,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
	Kind      string `json:"kind"`
	Message   string `json:"message"`
	CreatedAt string `json:"created_at"`
}

// ListEvents возвращает последние события, новые первыми
func (s *Store) ListEvents(ctx context.Context, limit int) ([]Event, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, COALESCE(cluster_id::text, ''), COALESCE(node_id::text, ''), kind, message,
		to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"')
		FROM events ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Event, error) {
		var e Event
		err := r.Scan(&e.ID, &e.ClusterID, &e.NodeID, &e.Kind, &e.Message, &e.CreatedAt)
		return e, err
	})
}
