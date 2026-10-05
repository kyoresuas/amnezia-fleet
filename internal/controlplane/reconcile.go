package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/failover"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

// probeFreshness, результаты старше этого считаются устаревшими
func (s *Server) probeFreshness() time.Duration {
	return 3*s.cfg.ProbeInterval + 30*time.Second
}

// RunReconciler периодически пересчитывает здоровье адресов и публикует DNS
func (s *Server) RunReconciler(ctx context.Context) {
	t := time.NewTicker(s.cfg.DNSReconcileEvery)
	defer t.Stop()
	for {
		if err := s.reconcileAll(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("согласование DNS", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// reconcileAll обрабатывает все кластеры
func (s *Server) reconcileAll(ctx context.Context) error {
	views, err := s.probeViews(ctx)
	if err != nil {
		return err
	}
	clusters, err := s.store.ListClusters(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, c := range clusters {
		if err := s.reconcileClusterWith(ctx, c, views); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c.Name, err))
		}
	}
	return errors.Join(errs...)
}

// reconcileCluster обрабатывает один кластер (ручная синхронизация из API)
func (s *Server) reconcileCluster(ctx context.Context, c model.Cluster) error {
	views, err := s.probeViews(ctx)
	if err != nil {
		return err
	}
	return s.reconcileClusterWith(ctx, c, views)
}

// probeViews группирует результаты проб по адресам, отбрасывая сломанные пробы
func (s *Server) probeViews(ctx context.Context) (map[string][]failover.ProbeView, error) {
	statuses, err := s.store.ListProbeStatuses(ctx, s.probeFreshness())
	if err != nil {
		return nil, err
	}
	total := map[string]int{}
	failed := map[string]int{}
	for _, st := range statuses {
		total[st.ProbeID]++
		if !st.OK {
			failed[st.ProbeID]++
		}
	}
	views := map[string][]failover.ProbeView{}
	for _, st := range statuses {
		if total[st.ProbeID] >= 2 && failed[st.ProbeID] == total[st.ProbeID] {
			continue
		}
		views[st.AddressID] = append(views[st.AddressID], failover.ProbeView{OK: st.OK, Streak: st.Streak})
	}
	return views, nil
}

// reconcileClusterWith обновляет здоровье адресов и DNS кластера
func (s *Server) reconcileClusterWith(ctx context.Context, c model.Cluster, views map[string][]failover.ProbeView) error {
	nodes, err := s.store.ListNodes(ctx, c.ID)
	if err != nil {
		return err
	}
	now := time.Now()
	var candidates []failover.Candidate
	hasV6 := false
	for _, n := range nodes {
		alive := failover.NodeAlive(n, s.cfg.NodeStaleAfter, now)
		for _, a := range n.Addresses {
			health := failover.AggregateHealth(views[a.ID], s.cfg.ProbeFailThreshold)
			if health != a.Health {
				if _, err := s.store.SetAddressHealth(ctx, a.ID, health); err != nil {
					return err
				}
				msg := fmt.Sprintf("адрес %s (%s): %s -> %s", a.IP, n.Name, a.Health, health)
				if a.State == model.AddressBlocked && health == failover.HealthUp {
					msg += "; адрес заблокирован, но снова доступен, можно вернуть вручную"
				}
				_ = s.store.AddEvent(ctx, c.ID, n.ID, "address.health", msg)
				a.Health = health
			}
			// узел жив, а пробы не проходят, значит блокировка
			if s.cfg.AutoBlock && health == failover.HealthDown && alive &&
				(a.State == model.AddressActive || a.State == model.AddressSpare) {
				blocked := model.AddressBlocked
				if _, err := s.store.UpdateAddress(ctx, a.ID, store.AddressPatch{State: &blocked}); err != nil {
					return err
				}
				_ = s.store.AddEvent(ctx, c.ID, n.ID, "address.blocked",
					fmt.Sprintf("адрес %s (%s) недоступен для наблюдателей при живом агенте, помечен заблокированным", a.IP, n.Name))
				a.State = blocked
			}
			if a.IP.Is6() {
				hasV6 = true
			}
			candidates = append(candidates, failover.Candidate{Address: a, NodeState: n.State, NodeAlive: alive})
		}
	}

	cur, err := s.store.GetDNSState(ctx, c.ID)
	if err != nil {
		return err
	}
	v4 := failover.Select(c.DNSMode, candidates, cur.Records, true)
	v6 := failover.Select(c.DNSMode, candidates, cur.Records, false)
	next := append(slices.Clone(v4.Records), v6.Records...)

	kept := v4.Kept && len(v4.Records) > 0
	if s.noCandidates.flip(c.ID, kept) && kept {
		_ = s.store.AddEvent(ctx, c.ID, "", "dns.no_candidates",
			"нет пригодных IPv4-адресов, в DNS оставлены прежние: "+joinAddrs(v4.Records))
	}
	if sameAddrs(next, cur.Records) && cur.Error == "" && cur.SyncedAt != nil {
		return nil
	}

	if err := s.dns.SetRecords(ctx, c.Hostname, "A", v4.Records, c.DNSTTL); err != nil {
		_ = s.store.SaveDNSState(ctx, c.ID, nil, err.Error())
		return err
	}
	if hasV6 || len(v6.Records) > 0 || hasFamily(cur.Records, false) {
		if err := s.dns.SetRecords(ctx, c.Hostname, "AAAA", v6.Records, c.DNSTTL); err != nil {
			_ = s.store.SaveDNSState(ctx, c.ID, nil, err.Error())
			return err
		}
	}
	if err := s.store.SaveDNSState(ctx, c.ID, next, ""); err != nil {
		return err
	}
	if !sameAddrs(next, cur.Records) {
		_ = s.store.AddEvent(ctx, c.ID, "", "dns.changed",
			fmt.Sprintf("%s: %s -> %s", c.Hostname, joinAddrs(cur.Records), joinAddrs(next)))
		s.log.Info("DNS обновлён", "cluster", c.Name, "hostname", c.Hostname, "records", next)
	}
	return nil
}

type flagSet struct {
	mu sync.Mutex
	m  map[string]bool
}

// flip сохраняет значение и возвращает true, если оно изменилось
func (f *flagSet) flip(key string, v bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.m == nil {
		f.m = map[string]bool{}
	}
	changed := f.m[key] != v
	f.m[key] = v
	return changed
}

// sameAddrs сравнивает наборы адресов без учёта порядка
func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	as, bs := slices.Clone(a), slices.Clone(b)
	slices.SortFunc(as, func(x, y netip.Addr) int { return x.Compare(y) })
	slices.SortFunc(bs, func(x, y netip.Addr) int { return x.Compare(y) })
	return slices.Equal(as, bs)
}

// hasFamily сообщает, есть ли в списке адреса нужного семейства
func hasFamily(addrs []netip.Addr, is4 bool) bool {
	return slices.ContainsFunc(addrs, func(a netip.Addr) bool { return a.Is4() == is4 })
}

// joinAddrs форматирует список адресов для журнала
func joinAddrs(addrs []netip.Addr) string {
	if len(addrs) == 0 {
		return "(пусто)"
	}
	out := ""
	for i, a := range addrs {
		if i > 0 {
			out += ", "
		}
		out += a.String()
	}
	return out
}

// publishAddress вручную делает адрес единственным опубликованным в своём семействе
func (s *Server) publishAddress(w http.ResponseWriter, r *http.Request) {
	var req struct {
		AddressID string `json:"address_id"`
	}
	if err := readJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	c, err := s.store.GetCluster(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if c.DNSMode == model.DNSModeAll {
		writeError(w, http.StatusConflict, "в режиме all публикуются все живые адреса")
		return
	}
	nodes, err := s.store.ListNodes(r.Context(), c.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	var addr model.Address
	var node model.Node
	for _, n := range nodes {
		for _, a := range n.Addresses {
			if a.ID == req.AddressID {
				addr, node = a, n
			}
		}
	}
	switch {
	case addr.ID == "":
		writeError(w, http.StatusNotFound, "адрес не найден в кластере")
		return
	case node.State != model.NodeActive:
		writeError(w, http.StatusConflict, "сервер выключен или выводится")
		return
	case !failover.NodeAlive(node, s.cfg.NodeStaleAfter, time.Now()):
		writeError(w, http.StatusConflict, "сервер не на связи")
		return
	case addr.State != model.AddressActive && addr.State != model.AddressSpare:
		writeError(w, http.StatusConflict, "адрес заблокирован или выключен")
		return
	}
	cur, err := s.store.GetDNSState(r.Context(), c.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	records := []netip.Addr{addr.IP}
	for _, a := range cur.Records {
		if a.Is4() != addr.IP.Is4() {
			records = append(records, a)
		}
	}
	recordType := "A"
	if addr.IP.Is6() {
		recordType = "AAAA"
	}
	if err := s.dns.SetRecords(r.Context(), c.Hostname, recordType, []netip.Addr{addr.IP}, c.DNSTTL); err != nil {
		_ = s.store.SaveDNSState(r.Context(), c.ID, nil, err.Error())
		writeError(w, http.StatusBadGateway, "DNS: "+err.Error())
		return
	}
	if err := s.store.SaveDNSState(r.Context(), c.ID, records, ""); err != nil {
		s.writeStoreError(w, err)
		return
	}
	_ = s.store.AddEvent(r.Context(), c.ID, node.ID, "dns.manual",
		fmt.Sprintf("%s: вручную %s -> %s (%s)", c.Hostname, joinAddrs(cur.Records), joinAddrs(records), node.Name))
	st, err := s.store.GetDNSState(r.Context(), c.ID)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}
