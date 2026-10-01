package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

// monthStart возвращает начало текущего календарного месяца в UTC
func monthStart(now time.Time) time.Time {
	now = now.UTC()
	return time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
}

// timeRange читает параметры from и to (RFC 3339)
func timeRange(r *http.Request) (time.Time, time.Time, error) {
	now := time.Now().UTC()
	from, to := monthStart(now), now
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, fmt.Errorf("from: %w", err)
		}
		from = t
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return from, to, fmt.Errorf("to: %w", err)
		}
		to = t
	}
	if !from.Before(to) {
		return from, to, fmt.Errorf("from должен быть раньше to")
	}
	return from, to, nil
}

// queryInt читает целый параметр запроса с ограничением сверху
func queryInt(r *http.Request, key string, def, max int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(key))
	if err != nil || v <= 0 {
		return def
	}
	return min(v, max)
}

// requireTelemetry отвечает 503, если ClickHouse не настроен
func (s *Server) requireTelemetry(w http.ResponseWriter) bool {
	if s.tele == nil {
		writeError(w, http.StatusServiceUnavailable, "телеметрия отключена: FLEET_CLICKHOUSE_URL не задан")
		return false
	}
	return true
}

// userPeerIDs возвращает идентификаторы пиров пользователя
func (s *Server) userPeerIDs(ctx context.Context, userID string) ([]string, error) {
	peers, err := s.store.ListPeers(ctx, store.PeerFilter{UserID: userID})
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(peers))
	for i, p := range peers {
		ids[i] = p.ID
	}
	return ids, nil
}

type usageRow struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
	PeerID   string `json:"peer_id"`
	PeerName string `json:"peer_name"`
	Rx       uint64 `json:"rx"`
	Tx       uint64 `json:"tx"`
	Total    uint64 `json:"total"`
}

// statsUsage возвращает трафик всех пиров за период, тяжёлые первыми
func (s *Server) statsUsage(w http.ResponseWriter, r *http.Request) {
	if !s.requireTelemetry(w) {
		return
	}
	from, to, err := timeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	totals, err := s.tele.UsageTotals(r.Context(), from, to)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	peers, err := s.store.ListPeers(r.Context(), store.PeerFilter{})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	userNames := make(map[string]string, len(users))
	for _, u := range users {
		userNames[u.ID] = u.Name
	}
	out := make([]usageRow, 0, len(totals))
	byPeer := make(map[string]int, len(peers))
	for i, p := range peers {
		byPeer[p.ID] = i
	}
	for _, t := range totals {
		row := usageRow{PeerID: t.PeerID, Rx: t.Rx, Tx: t.Tx, Total: t.Rx + t.Tx}
		if i, ok := byPeer[t.PeerID]; ok {
			row.PeerName, row.UserID = peers[i].Name, peers[i].UserID
			row.UserName = userNames[row.UserID]
		}
		out = append(out, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"from": from, "to": to, "peers": out})
}

// userUsage возвращает временной ряд трафика пользователя
func (s *Server) userUsage(w http.ResponseWriter, r *http.Request) {
	if !s.requireTelemetry(w) {
		return
	}
	from, to, err := timeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids, err := s.userPeerIDs(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	step := queryInt(r, "step", 3600, 86400*31)
	points, err := s.tele.UsageSeries(r.Context(), ids, from, to, max(step, 60))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(points))
}

// userDestinations возвращает, куда пользователь тратит трафик
func (s *Server) userDestinations(w http.ResponseWriter, r *http.Request) {
	if !s.requireTelemetry(w) {
		return
	}
	from, to, err := timeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids, err := s.userPeerIDs(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	byDomain := r.URL.Query().Get("by") != "ip"
	out, err := s.tele.TopDestinations(r.Context(), ids, from, to, byDomain, queryInt(r, "limit", 50, 1000))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// userDNSLog возвращает последние DNS-запросы пользователя
func (s *Server) userDNSLog(w http.ResponseWriter, r *http.Request) {
	if !s.requireTelemetry(w) {
		return
	}
	from, to, err := timeRange(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	ids, err := s.userPeerIDs(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	out, err := s.tele.DNSLog(r.Context(), ids, from, to, queryInt(r, "limit", 200, 5000))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// listEvents возвращает журнал событий
func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListEvents(r.Context(), queryInt(r, "limit", 100, 1000))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// RunLimits следит за лимитами и сроками
func (s *Server) RunLimits(ctx context.Context) {
	t := time.NewTicker(s.cfg.LimitsCheckEvery)
	defer t.Stop()
	lastRun := time.Now().Add(-s.cfg.LimitsCheckEvery)
	for {
		now := time.Now()
		if _, err := s.store.BumpExpiredUsers(ctx, lastRun); err != nil && ctx.Err() == nil {
			s.log.Error("проверка сроков", "err", err)
		}
		lastRun = now
		if err := s.enforceTrafficLimits(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("проверка лимитов", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// enforceTrafficLimits приостанавливает превысивших месячный лимит
func (s *Server) enforceTrafficLimits(ctx context.Context) error {
	if s.tele == nil {
		return nil
	}
	users, err := s.store.ListUsers(ctx)
	if err != nil {
		return err
	}
	limited := map[string]int64{}
	for _, u := range users {
		if u.TrafficLimitBytes != nil && u.Status == "active" {
			limited[u.ID] = *u.TrafficLimitBytes
		}
	}
	if len(limited) == 0 {
		return nil
	}
	now := time.Now()
	totals, err := s.tele.UsageTotals(ctx, monthStart(now), now.Add(time.Minute))
	if err != nil {
		return err
	}
	peers, err := s.store.ListPeers(ctx, store.PeerFilter{})
	if err != nil {
		return err
	}
	owner := make(map[string]string, len(peers))
	for _, p := range peers {
		owner[p.ID] = p.UserID
	}
	used := map[string]uint64{}
	for _, t := range totals {
		used[owner[t.PeerID]] += t.Rx + t.Tx
	}
	for userID, limit := range limited {
		if used[userID] < uint64(limit) {
			continue
		}
		changed, err := s.store.SuspendUser(ctx, userID)
		if err != nil {
			return err
		}
		if changed {
			_ = s.store.AddEvent(ctx, "", "", "user.limit",
				fmt.Sprintf("пользователь %s превысил месячный лимит (%d из %d байт) и приостановлен", userID, used[userID], limit))
		}
	}
	return nil
}
