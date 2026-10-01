//go:build linux

// Package flows, учёт трафика по назначениям через conntrack
package flows

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
)

type Tunnel interface {
	InTunnel(netip.Addr) bool
	IsGateway(netip.Addr) bool
	PeerByAddr(netip.Addr) (string, bool)
}

type Domains interface {
	Domain(src, dst netip.Addr) string
}

type ctKey struct {
	id    uint32
	src   netip.AddrPort
	dst   netip.AddrPort
	proto uint8
}

type ctLast struct {
	up, down     uint64
	pktUp, pktDn uint64
	seen         time.Time
}

type bucketKey struct {
	minute time.Time
	peerID string
	proto  uint8
	dst    netip.Addr
	port   uint16
	domain string
}

type Collector struct {
	tunnel  Tunnel
	domains Domains
	every   time.Duration
	limit   int
	log     *slog.Logger

	mu        sync.Mutex
	last      map[ctKey]ctLast
	buckets   map[bucketKey]*agentapi.Flow
	dropped   uint64
	baselined bool
}

// New создаёт сборщик
func New(tunnel Tunnel, domains Domains, every time.Duration, limit int, log *slog.Logger) *Collector {
	return &Collector{
		tunnel: tunnel, domains: domains, every: every, limit: limit, log: log,
		last: map[ctKey]ctLast{}, buckets: map[bucketKey]*agentapi.Flow{},
	}
}

// Run опрашивает таблицу conntrack и слушает события удаления соединений
func (c *Collector) Run(ctx context.Context) {
	go c.listenLoop(ctx)
	t := time.NewTicker(c.every)
	defer t.Stop()
	for {
		if err := c.dump(); err != nil && ctx.Err() == nil {
			c.log.Warn("дамп conntrack", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// dump учитывает приросты всех живых соединений туннеля
func (c *Collector) dump() error {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	flows, err := conn.Dump(nil)
	if err != nil {
		return err
	}
	now := time.Now()
	alive := make(map[ctKey]bool, len(flows))
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range flows {
		if k, ok := c.account(&flows[i], now, c.baselined); ok {
			alive[k] = true
		}
	}
	c.baselined = true
	for k := range c.last {
		if !alive[k] {
			delete(c.last, k)
		}
	}
	return nil
}

// listenLoop слушает удаление соединений
func (c *Collector) listenLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if err := c.listen(ctx); err != nil && ctx.Err() == nil {
			c.log.Warn("события conntrack", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// listen обрабатывает события до ошибки или отмены контекста
func (c *Collector) listen(ctx context.Context) error {
	conn, err := conntrack.Dial(nil)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadBuffer(8 << 20)
	// без ENOBUFS, пропуски подхватит дамп
	_ = conn.SetOption(netlink.NoENOBUFS, true)
	events := make(chan conntrack.Event, 4096)
	errs, err := conn.Listen(events, 2, []netfilter.NetlinkGroup{netfilter.GroupCTDestroy})
	if err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case ev := <-events:
			if ev.Type != conntrack.EventDestroy || ev.Flow == nil {
				continue
			}
			c.mu.Lock()
			if k, ok := c.account(ev.Flow, time.Now(), c.baselined); ok {
				delete(c.last, k)
			}
			c.mu.Unlock()
		}
	}
}

// account добавляет прирост счётчиков соединения в минутный агрегат
func (c *Collector) account(f *conntrack.Flow, now time.Time, count bool) (ctKey, bool) {
	src := f.TupleOrig.IP.SourceAddress.Unmap()
	dst := f.TupleOrig.IP.DestinationAddress.Unmap()
	if !c.tunnel.InTunnel(src) || c.tunnel.IsGateway(dst) || c.tunnel.InTunnel(dst) {
		return ctKey{}, false
	}
	peerID, ok := c.tunnel.PeerByAddr(src)
	if !ok {
		return ctKey{}, false
	}
	proto := f.TupleOrig.Proto.Protocol
	k := ctKey{
		id:    f.ID,
		src:   netip.AddrPortFrom(src, f.TupleOrig.Proto.SourcePort),
		dst:   netip.AddrPortFrom(dst, f.TupleOrig.Proto.DestinationPort),
		proto: proto,
	}
	cur := ctLast{
		up: f.CountersOrig.Bytes, down: f.CountersReply.Bytes,
		pktUp: f.CountersOrig.Packets, pktDn: f.CountersReply.Packets, seen: now,
	}
	prev, known := c.last[k]
	c.last[k] = cur
	if !count {
		return k, true
	}
	up, down := delta(cur.up, prev.up), delta(cur.down, prev.down)
	pu, pd := delta(cur.pktUp, prev.pktUp), delta(cur.pktDn, prev.pktDn)
	if known && up == 0 && down == 0 {
		return k, true
	}
	bk := bucketKey{
		minute: now.UTC().Truncate(time.Minute),
		peerID: peerID,
		proto:  proto,
		dst:    dst,
		port:   f.TupleOrig.Proto.DestinationPort,
		domain: c.domains.Domain(src, dst),
	}
	b, ok := c.buckets[bk]
	if !ok {
		if len(c.buckets) >= c.limit {
			c.dropped++
			return k, true
		}
		b = &agentapi.Flow{Minute: bk.minute, PeerID: peerID, Proto: proto, DstIP: dst, DstPort: bk.port, Domain: bk.domain}
		c.buckets[bk] = b
	}
	b.BytesUp += up
	b.BytesDown += down
	b.PacketsUp += pu
	b.PacketsDown += pd
	if !known {
		b.Connections++
	}
	return k, true
}

// delta возвращает прирост счётчика
func delta(cur, prev uint64) uint64 {
	if cur >= prev {
		return cur - prev
	}
	return cur
}

// Drain забирает накопленные агрегаты и счётчик выброшенных
func (c *Collector) Drain() ([]agentapi.Flow, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]agentapi.Flow, 0, len(c.buckets))
	for _, b := range c.buckets {
		out = append(out, *b)
	}
	d := c.dropped
	c.buckets = map[bucketKey]*agentapi.Flow{}
	c.dropped = 0
	return out, d
}

// Requeue возвращает неотправленные агрегаты
func (c *Collector) Requeue(flows []agentapi.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, f := range flows {
		bk := bucketKey{minute: f.Minute, peerID: f.PeerID, proto: f.Proto, dst: f.DstIP, port: f.DstPort, domain: f.Domain}
		b, ok := c.buckets[bk]
		if !ok {
			if len(c.buckets) >= c.limit {
				c.dropped++
				continue
			}
			cp := f
			c.buckets[bk] = &cp
			continue
		}
		b.BytesUp += f.BytesUp
		b.BytesDown += f.BytesDown
		b.PacketsUp += f.PacketsUp
		b.PacketsDown += f.PacketsDown
		b.Connections += f.Connections
	}
}
