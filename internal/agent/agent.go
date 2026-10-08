//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/agent/awgnl"
	"github.com/kyoresuas/amnezia-fleet/internal/agent/dnsproxy"
	"github.com/kyoresuas/amnezia-fleet/internal/agent/flows"
	"github.com/kyoresuas/amnezia-fleet/internal/agent/netsetup"
	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

type Agent struct {
	cfg   Config
	log   *slog.Logger
	api   *apiClient
	index *PeerIndex
	dns   *dnsproxy.Proxy
	flows *flows.Collector

	mu       sync.Mutex
	nl       *awgnl.Client
	state    *agentapi.DesiredState
	applied  int64
	lastErr  string
	dnsAddrs []netip.Addr

	exitAlive bool
	synced    bool
	counters  map[awg.Key][2]uint64
	baselined bool
	pending   map[string]*agentapi.PeerUsage
}

// New создаёт агента
func New(cfg Config, log *slog.Logger) *Agent {
	a := &Agent{
		cfg:      cfg,
		log:      log,
		api:      newAPIClient(cfg.ServerURL, cfg.Token),
		index:    NewPeerIndex(),
		counters: map[awg.Key][2]uint64{},
		pending:  map[string]*agentapi.PeerUsage{},
	}
	a.dns = dnsproxy.New(cfg.DNSUpstreams, a.index, true, cfg.MaxBufferedDNS)
	a.flows = flows.New(a.index, a.dns, cfg.FlowsEvery, cfg.MaxBufferedFlows, log)
	return a
}

// Run работает до отмены контекста
func (a *Agent) Run(ctx context.Context) error {
	if st, err := a.loadState(); err == nil {
		a.log.Info("применяю сохранённое состояние", "revision", st.Revision)
		a.applyAndRecord(st)
	} else if !errors.Is(err, os.ErrNotExist) {
		a.log.Warn("сохранённое состояние не прочитано", "err", err)
	}
	go a.flows.Run(ctx)
	go a.reportLoop(ctx)
	go a.sweepLoop(ctx)
	a.stateLoop(ctx)
	a.dns.Stop()
	return nil
}

// stateLoop забирает состояние long-poll'ом и применяет каждое новое
func (a *Agent) stateLoop(ctx context.Context) {
	backoff := time.Second
	for ctx.Err() == nil {
		a.mu.Lock()
		known := int64(0)
		// сохранённое состояние могло записать старая версия агента, поэтому первый запрос всегда полный
		if a.synced && a.state != nil && a.applied == a.state.Revision {
			known = a.applied
		}
		a.mu.Unlock()
		st, err := a.api.fetchState(ctx, known)
		switch {
		case errors.Is(err, errNotModified):
			backoff = time.Second
			continue
		case err != nil:
			if ctx.Err() == nil {
				a.log.Warn("получение состояния", "err", err, "retry_in", backoff)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		if err := a.saveState(st); err != nil {
			a.log.Warn("сохранение состояния", "err", err)
		}
		a.applyAndRecord(st)
		a.mu.Lock()
		a.synced = true
		a.mu.Unlock()
		if a.lastError() != "" {
			// повтор без ожидания новой ревизии
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
		}
	}
}

// lastError возвращает последнюю ошибку применения
func (a *Agent) lastError() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

// applyAndRecord применяет состояние и запоминает результат для heartbeat
func (a *Agent) applyAndRecord(st agentapi.DesiredState) {
	err := a.apply(st)
	a.mu.Lock()
	defer a.mu.Unlock()
	a.state = &st
	if err != nil {
		a.lastErr = err.Error()
		a.log.Error("применение состояния", "revision", st.Revision, "err", err)
		return
	}
	if a.applied != st.Revision {
		a.log.Info("состояние применено", "revision", st.Revision, "peers", len(st.Peers), "enabled", st.Enabled)
	}
	a.applied = st.Revision
	a.lastErr = ""
}

// apply приводит узел к желаемому состоянию
func (a *Agent) apply(st agentapi.DesiredState) error {
	a.index.Update(st)
	a.dns.SetLogging(st.Telemetry.DNSQueries)
	if !st.Enabled {
		a.stopDNS()
		a.dns.SetExit(nil, netip.Addr{}, nil)
		return errors.Join(teardownExit(), netsetup.DeleteLink(a.cfg.Iface), netsetup.RemoveFirewall())
	}
	addrs := []netip.Prefix{st.Interface.AddressV4}
	if st.Interface.AddressV6.IsValid() {
		addrs = append(addrs, st.Interface.AddressV6)
	}
	if err := netsetup.EnsureLink(a.cfg.Iface, st.Interface.MTU, addrs); err != nil {
		return err
	}
	if err := netsetup.ApplyFirewall(netsetup.FirewallSpec{
		Iface: a.cfg.Iface, SubnetV4: st.Interface.AddressV4.Masked(), SubnetV6: st.Interface.AddressV6.Masked(),
		Gateway: st.Interface.AddressV4.Addr(), BlockDoH: st.Exit != nil,
	}); err != nil {
		return err
	}
	if err := netsetup.Sysctls(st.Interface.AddressV6.IsValid()); err != nil {
		return err
	}
	nl, err := a.netlink()
	if err != nil {
		return err
	}
	dev, err := nl.Device(a.cfg.Iface)
	if err != nil {
		a.resetNetlink()
		return err
	}
	cfg := diffDevice(dev, st)
	if cfg.PrivateKey != nil || cfg.ListenPort != nil || cfg.Params != nil || len(cfg.Peers) > 0 {
		if err := nl.Configure(a.cfg.Iface, cfg); err != nil {
			a.resetNetlink()
			return err
		}
	}
	gateways := []netip.Addr{st.Interface.AddressV4.Addr()}
	if st.Interface.AddressV6.IsValid() {
		gateways = append(gateways, st.Interface.AddressV6.Addr())
	}
	if err := a.ensureDNS(gateways); err != nil {
		return err
	}
	return a.applyExit(st.Exit, a.cfg.Iface)
}

// netlink возвращает соединение с модулем, открывая его при необходимости
func (a *Agent) netlink() (*awgnl.Client, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nl != nil {
		return a.nl, nil
	}
	nl, err := awgnl.Dial()
	if err != nil {
		return nil, err
	}
	a.nl = nl
	return nl, nil
}

// resetNetlink сбрасывает соединение после ошибки
func (a *Agent) resetNetlink() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.nl != nil {
		_ = a.nl.Close()
		a.nl = nil
	}
}

// ensureDNS запускает резолвер на адресах шлюза
func (a *Agent) ensureDNS(addrs []netip.Addr) error {
	a.mu.Lock()
	same := slices.Equal(a.dnsAddrs, addrs)
	a.mu.Unlock()
	if same {
		return nil
	}
	a.dns.Stop()
	if err := a.dns.Start(addrs); err != nil {
		return fmt.Errorf("DNS-резолвер: %w", err)
	}
	a.mu.Lock()
	a.dnsAddrs = slices.Clone(addrs)
	a.mu.Unlock()
	return nil
}

// stopDNS останавливает резолвер
func (a *Agent) stopDNS() {
	a.dns.Stop()
	a.mu.Lock()
	a.dnsAddrs = nil
	a.mu.Unlock()
}

// serverParams оставляет только серверные параметры
func serverParams(p awg.Params) awg.Params {
	p.I1, p.I2, p.I3, p.I4, p.I5 = "", "", "", "", ""
	p.PersistentKeepalive = awg.Range16{}
	return p
}

// diffDevice вычисляет минимальный набор изменений
func diffDevice(dev *awgnl.Device, st agentapi.DesiredState) awgnl.Config {
	var cfg awgnl.Config
	if dev.PrivateKey != st.Interface.PrivateKey {
		k := st.Interface.PrivateKey
		cfg.PrivateKey = &k
	}
	if dev.ListenPort != st.Interface.ListenPort {
		port := st.Interface.ListenPort
		cfg.ListenPort = &port
	}
	want := serverParams(st.Interface.Params)
	if serverParams(dev.Params) != want {
		cfg.Params = &want
	}

	desired := make(map[awg.Key]agentapi.PeerSpec, len(st.Peers))
	for _, p := range st.Peers {
		desired[p.PublicKey] = p
	}
	current := make(map[awg.Key]awgnl.Peer, len(dev.Peers))
	for _, p := range dev.Peers {
		current[p.PublicKey] = p
		if _, ok := desired[p.PublicKey]; !ok {
			cfg.Peers = append(cfg.Peers, awgnl.PeerConfig{PublicKey: p.PublicKey, Remove: true})
		}
	}
	for _, want := range st.Peers {
		cur, exists := current[want.PublicKey]
		if exists && cur.PresharedKey == want.PresharedKey && samePrefixes(cur.AllowedIPs, want.AllowedIPs) {
			continue
		}
		psk := want.PresharedKey
		cfg.Peers = append(cfg.Peers, awgnl.PeerConfig{
			PublicKey: want.PublicKey, PresharedKey: &psk, ReplaceAllowedIPs: true, AllowedIPs: want.AllowedIPs,
		})
	}
	return cfg
}

// samePrefixes сравнивает наборы префиксов без учёта порядка
func samePrefixes(a, b []netip.Prefix) bool {
	if len(a) != len(b) {
		return false
	}
	set := make(map[netip.Prefix]bool, len(a))
	for _, p := range a {
		set[p.Masked()] = true
	}
	for _, p := range b {
		if !set[p.Masked()] {
			return false
		}
	}
	return true
}

// reportLoop периодически собирает счётчики и отправляет отчёт
func (a *Agent) reportLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.ReportEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.report(ctx)
	}
}

// report собирает отчёт и отправляет его
func (a *Agent) report(ctx context.Context) {
	now := time.Now()
	peerStats := a.sampleCounters(now)
	a.checkExit(now)
	a.mu.Lock()
	rep := agentapi.Report{
		AgentVersion:    Version,
		AppliedRevision: a.applied,
		LastError:       a.lastErr,
		CollectedAt:     now,
		Peers:           peerStats,
	}
	flowsOn := a.state != nil && a.state.Telemetry.Flows
	for _, u := range a.pending {
		rep.Usage = append(rep.Usage, *u)
	}
	a.mu.Unlock()

	flowBatch, droppedFlows := a.flows.Drain()
	if !flowsOn {
		flowBatch = nil
	}
	queries, droppedDNS := a.dns.Drain()
	rep.Flows, rep.DNSQueries = flowBatch, queries
	rep.Dropped = agentapi.DroppedStats{Flows: droppedFlows, DNSQueries: droppedDNS}

	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := a.api.sendReport(sendCtx, rep); err != nil {
		if ctx.Err() == nil {
			a.log.Warn("отправка отчёта", "err", err)
		}
		a.flows.Requeue(flowBatch)
		a.dns.Requeue(queries)
		return
	}
	a.mu.Lock()
	clear(a.pending)
	a.mu.Unlock()
}

// sampleCounters копит приросты трафика и возвращает состояние пиров
func (a *Agent) sampleCounters(now time.Time) []agentapi.PeerStat {
	nl, err := a.netlink()
	if err != nil {
		return nil
	}
	dev, err := nl.Device(a.cfg.Iface)
	if err != nil {
		if !errors.Is(err, awgnl.ErrNotFound) {
			a.resetNetlink()
		}
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	seen := make(map[awg.Key]bool, len(dev.Peers))
	stats := make([]agentapi.PeerStat, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		seen[p.PublicKey] = true
		id, ok := a.index.PeerByKey(p.PublicKey)
		prev, known := a.counters[p.PublicKey]
		a.counters[p.PublicKey] = [2]uint64{p.RxBytes, p.TxBytes}
		if !ok {
			continue
		}
		st := agentapi.PeerStat{PeerID: id, Endpoint: p.Endpoint}
		if !p.LastHandshake.IsZero() {
			hs := p.LastHandshake
			st.LastHandshake = &hs
		}
		stats = append(stats, st)
		// первый замер только задаёт базу
		if !a.baselined {
			continue
		}
		var rx, tx uint64
		if known {
			rx, tx = counterDelta(p.RxBytes, prev[0]), counterDelta(p.TxBytes, prev[1])
		} else {
			rx, tx = p.RxBytes, p.TxBytes
		}
		if rx == 0 && tx == 0 {
			continue
		}
		u := a.pending[id]
		if u == nil {
			u = &agentapi.PeerUsage{PeerID: id, From: now}
			a.pending[id] = u
		}
		u.Rx += rx
		u.Tx += tx
		u.To = now
	}
	for k := range a.counters {
		if !seen[k] {
			delete(a.counters, k)
		}
	}
	a.baselined = true
	return stats
}

// counterDelta возвращает прирост
func counterDelta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// sweepLoop чистит устаревшие соответствия доменов
func (a *Agent) sweepLoop(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.dns.Sweep()
		}
	}
}

// loadState читает сохранённое состояние
func (a *Agent) loadState() (agentapi.DesiredState, error) {
	var st agentapi.DesiredState
	raw, err := os.ReadFile(a.cfg.StateFile)
	if err != nil {
		return st, err
	}
	err = json.Unmarshal(raw, &st)
	return st, err
}

// saveState атомарно сохраняет состояние
func (a *Agent) saveState(st agentapi.DesiredState) error {
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.StateFile), 0o700); err != nil {
		return err
	}
	tmp := a.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.cfg.StateFile)
}
