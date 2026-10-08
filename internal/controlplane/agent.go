package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/model"
	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

const longPollWait = 25 * time.Second

const longPollTick = time.Second

const probePeerPrefix = "probe:"

// buildDesiredState собирает полное желаемое состояние узла
func (s *Server) buildDesiredState(ctx context.Context, n model.Node) (agentapi.DesiredState, error) {
	c, err := s.store.GetCluster(ctx, n.ClusterID)
	if err != nil {
		return agentapi.DesiredState{}, err
	}
	peers, err := s.store.ListActivePeers(ctx, c.ID)
	if err != nil {
		return agentapi.DesiredState{}, err
	}
	probes, err := s.store.ListProbes(ctx)
	if err != nil {
		return agentapi.DesiredState{}, err
	}
	st := agentapi.DesiredState{
		Revision:  c.Revision,
		ClusterID: c.ID,
		NodeID:    n.ID,
		Enabled:   n.State != model.NodeDisabled,
		Interface: agentapi.InterfaceSpec{
			PrivateKey: c.PrivateKey,
			ListenPort: c.ListenPort,
			AddressV4:  netip.PrefixFrom(c.GatewayV4(), c.SubnetV4.Bits()),
			MTU:        c.MTU,
			Params:     c.Params,
		},
		Telemetry: agentapi.TelemetryFlags{Flows: s.cfg.CollectFlows, DNSQueries: s.cfg.CollectDNS},
		Peers:     make([]agentapi.PeerSpec, 0, len(peers)+len(probes)),
	}
	if c.SubnetV6.IsValid() {
		st.Interface.AddressV6 = netip.PrefixFrom(c.GatewayV6(), c.SubnetV6.Bits())
	}
	for _, p := range peers {
		allowed := []netip.Prefix{netip.PrefixFrom(p.AddressV4, 32)}
		if p.AddressV6.IsValid() {
			allowed = append(allowed, netip.PrefixFrom(p.AddressV6, 128))
		}
		st.Peers = append(st.Peers, agentapi.PeerSpec{
			ID: p.ID, PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, AllowedIPs: allowed,
		})
	}
	for _, pr := range probes {
		// без AllowedIPs: только рукопожатие
		st.Peers = append(st.Peers, agentapi.PeerSpec{ID: probePeerPrefix + pr.ID, PublicKey: pr.PublicKey})
	}
	if st.Exit, err = s.exitSpec(ctx, c.ID, n.ID); err != nil {
		return agentapi.DesiredState{}, err
	}
	return st, nil
}

// exitSpec описывает подключение узла к выходу кластера, если он есть и включён
func (s *Server) exitSpec(ctx context.Context, clusterID, nodeID string) (*agentapi.ExitSpec, error) {
	e, err := s.store.GetExitByCluster(ctx, clusterID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !e.Enabled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	link, err := s.store.EnsureExitLink(ctx, e.ID, nodeID)
	if err != nil {
		return nil, err
	}
	dns, err := netip.ParseAddr(e.DNS)
	if err != nil {
		return nil, fmt.Errorf("DNS выхода: %w", err)
	}
	return &agentapi.ExitSpec{
		Endpoint:        netip.AddrPortFrom(e.Endpoint, e.ListenPort),
		ServerPublicKey: e.PublicKey,
		PrivateKey:      link.PrivateKey,
		Address:         link.Address,
		Params:          e.Params,
		Domains:         e.Domains,
		DNS:             dns,
	}, nil
}

// agentState отдаёт желаемое состояние
func (s *Server) agentState(w http.ResponseWriter, r *http.Request) {
	n, ok := s.authNode(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "неверный токен агента")
		return
	}
	known, _ := strconv.ParseInt(r.Header.Get(agentapi.HeaderKnownRevision), 10, 64)
	if known > 0 {
		deadline := time.NewTimer(longPollWait)
		defer deadline.Stop()
		tick := time.NewTicker(longPollTick)
		defer tick.Stop()
	wait:
		for {
			rev, err := s.store.ClusterRevision(r.Context(), n.ClusterID)
			if err != nil {
				s.writeStoreError(w, err)
				return
			}
			if rev != known {
				break
			}
			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				w.WriteHeader(http.StatusNotModified)
				return
			case <-tick.C:
				continue wait
			}
		}
		var err error
		if n, err = s.store.GetNode(r.Context(), n.ID); err != nil {
			s.writeStoreError(w, err)
			return
		}
	}
	st, err := s.buildDesiredState(r.Context(), n)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, st)
}

type onlineTracker struct {
	mu     sync.Mutex
	byNode map[string]nodePeers
}

type nodePeers struct {
	at    time.Time
	peers []agentapi.PeerStat
}

// newOnlineTracker создаёт пустой трекер
func newOnlineTracker() *onlineTracker {
	return &onlineTracker{byNode: map[string]nodePeers{}}
}

// set сохраняет снимок узла
func (o *onlineTracker) set(nodeID string, peers []agentapi.PeerStat) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.byNode[nodeID] = nodePeers{at: time.Now(), peers: peers}
}

type OnlinePeer struct {
	PeerID        string         `json:"peer_id"`
	NodeID        string         `json:"node_id"`
	Endpoint      netip.AddrPort `json:"endpoint,omitzero"`
	LastHandshake time.Time      `json:"last_handshake"`
}

const onlineWindow = 3 * time.Minute

// list возвращает пиров с свежим рукопожатием
func (o *onlineTracker) list(nodeIDs map[string]bool) []OnlinePeer {
	o.mu.Lock()
	defer o.mu.Unlock()
	best := map[string]OnlinePeer{}
	now := time.Now()
	for nodeID, snap := range o.byNode {
		if !nodeIDs[nodeID] {
			continue
		}
		for _, p := range snap.peers {
			if p.LastHandshake == nil || now.Sub(*p.LastHandshake) > onlineWindow || p.PeerID == "" || strings.HasPrefix(p.PeerID, probePeerPrefix) {
				continue
			}
			if cur, ok := best[p.PeerID]; !ok || p.LastHandshake.After(cur.LastHandshake) {
				best[p.PeerID] = OnlinePeer{PeerID: p.PeerID, NodeID: nodeID, Endpoint: p.Endpoint, LastHandshake: *p.LastHandshake}
			}
		}
	}
	out := make([]OnlinePeer, 0, len(best))
	for _, p := range best {
		out = append(out, p)
	}
	return out
}

// agentReport принимает heartbeat и телеметрию
func (s *Server) agentReport(w http.ResponseWriter, r *http.Request) {
	n, ok := s.authNode(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "неверный токен агента")
		return
	}
	var rep agentapi.Report
	if err := readJSON(r, &rep); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.TouchNode(r.Context(), n.ID, store.NodeReport{
		AgentVersion: rep.AgentVersion, AppliedRevision: rep.AppliedRevision, LastError: rep.LastError,
	}); err != nil {
		s.writeStoreError(w, err)
		return
	}
	if rep.LastError != "" && rep.LastError != n.LastError {
		_ = s.store.AddEvent(r.Context(), n.ClusterID, n.ID, "agent.error", rep.LastError)
	}
	s.online.set(n.ID, rep.Peers)
	if rep.Dropped.Flows > 0 || rep.Dropped.DNSQueries > 0 {
		s.log.Warn("агент выбросил телеметрию из-за переполнения буфера", "node", n.Name,
			"flows", rep.Dropped.Flows, "dns", rep.Dropped.DNSQueries)
	}
	if s.tele != nil {
		if err := s.tele.WriteReport(r.Context(), n.ClusterID, n.ID, rep); err != nil {
			s.log.Error("запись телеметрии", "node", n.Name, "err", err)
			writeError(w, http.StatusServiceUnavailable, "хранилище телеметрии недоступно")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// clusterOnline возвращает пиров кластера, подключённых прямо сейчас
func (s *Server) clusterOnline(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.ListNodes(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	ids := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		ids[n.ID] = true
	}
	writeJSON(w, http.StatusOK, s.online.list(ids))
}
