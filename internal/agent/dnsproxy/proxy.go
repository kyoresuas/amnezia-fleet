// Package dnsproxy, DNS-резолвер на шлюзе туннеля
package dnsproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
)

type PeerResolver interface {
	PeerByAddr(netip.Addr) (string, bool)
}

const domainTTL = 2 * time.Hour

const maxPerPeer = 20000

const upstreamTimeout = 3 * time.Second

type Proxy struct {
	upstreams []string
	peers     PeerResolver
	maxQueued int

	mu         sync.Mutex
	logQueries bool
	queue      []agentapi.DNSQuery
	dropped    uint64
	byPeer     map[netip.Addr]map[netip.Addr]domainEntry
	global     map[netip.Addr]domainEntry

	servers []*dns.Server
	client  *dns.Client
}

type domainEntry struct {
	name    string
	expires time.Time
}

// New создаёт резолвер
func New(upstreams []string, peers PeerResolver, logQueries bool, maxQueued int) *Proxy {
	return &Proxy{
		upstreams:  upstreams,
		peers:      peers,
		logQueries: logQueries,
		maxQueued:  maxQueued,
		byPeer:     map[netip.Addr]map[netip.Addr]domainEntry{},
		global:     map[netip.Addr]domainEntry{},
		client:     &dns.Client{Timeout: upstreamTimeout},
	}
}

// SetLogging включает или выключает журнал запросов
func (p *Proxy) SetLogging(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.logQueries = on
}

// Start запускает UDP- и TCP-серверы на указанных адресах (порт 53)
func (p *Proxy) Start(addrs []netip.Addr) error {
	for _, a := range addrs {
		listen := netip.AddrPortFrom(a, 53).String()
		for _, proto := range []string{"udp", "tcp"} {
			srv := &dns.Server{Addr: listen, Net: proto, Handler: dns.HandlerFunc(p.serve), ReusePort: true}
			started := make(chan error, 1)
			srv.NotifyStartedFunc = func() { started <- nil }
			go func() {
				if err := srv.ListenAndServe(); err != nil {
					started <- err
				}
			}()
			select {
			case err := <-started:
				if err != nil {
					p.Stop()
					return err
				}
			case <-time.After(5 * time.Second):
				p.Stop()
				return errors.New("DNS-сервер не запустился за 5 секунд")
			}
			p.servers = append(p.servers, srv)
		}
	}
	return nil
}

// Stop останавливает все серверы
func (p *Proxy) Stop() {
	for _, s := range p.servers {
		_ = s.Shutdown()
	}
	p.servers = nil
}

// serve обрабатывает один запрос: пересылает наверх и учитывает ответ
func (p *Proxy) serve(w dns.ResponseWriter, req *dns.Msg) {
	src := addrOf(w.RemoteAddr())
	peerID, ok := p.peers.PeerByAddr(src)
	if !ok {
		// чтобы не стать открытым резолвером
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	resp, err := p.forward(req, w.RemoteAddr().Network())
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
		p.record(src, peerID, req, nil, "SERVFAIL")
		return
	}
	_ = w.WriteMsg(resp)
	p.record(src, peerID, req, resp, dns.RcodeToString[resp.Rcode])
}

// forward пробует вышестоящие резолверы по очереди
func (p *Proxy) forward(req *dns.Msg, network string) (*dns.Msg, error) {
	c := *p.client
	c.Net = "udp"
	if strings.HasPrefix(network, "tcp") {
		c.Net = "tcp"
	}
	var lastErr error
	for _, up := range p.upstreams {
		ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout)
		resp, _, err := c.ExchangeContext(ctx, req, strings.TrimSpace(up))
		cancel()
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// record пишет запрос в журнал и обновляет домен-кеш по A/AAAA-ответам
func (p *Proxy) record(src netip.Addr, peerID string, req, resp *dns.Msg, rcode string) {
	if len(req.Question) == 0 {
		return
	}
	q := req.Question[0]
	name := strings.TrimSuffix(strings.ToLower(q.Name), ".")
	var answers []netip.Addr
	if resp != nil {
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if a, ok := netip.AddrFromSlice(v.A); ok {
					answers = append(answers, a.Unmap())
				}
			case *dns.AAAA:
				if a, ok := netip.AddrFromSlice(v.AAAA); ok {
					answers = append(answers, a)
				}
			}
		}
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(answers) > 0 {
		m := p.byPeer[src]
		if m == nil || len(m) > maxPerPeer {
			m = map[netip.Addr]domainEntry{}
			p.byPeer[src] = m
		}
		e := domainEntry{name: name, expires: now.Add(domainTTL)}
		for _, a := range answers {
			m[a] = e
			p.global[a] = e
		}
	}
	if !p.logQueries {
		return
	}
	if len(p.queue) >= p.maxQueued {
		p.dropped++
		return
	}
	p.queue = append(p.queue, agentapi.DNSQuery{
		At: now, PeerID: peerID, Name: name, Type: dns.TypeToString[q.Qtype], RCode: rcode, Answers: answers,
	})
}

// Domain возвращает домен, по которому клиент получил адрес назначения
func (p *Proxy) Domain(src, dst netip.Addr) string {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	if e, ok := p.byPeer[src.Unmap()][dst.Unmap()]; ok && e.expires.After(now) {
		return e.name
	}
	if e, ok := p.global[dst.Unmap()]; ok && e.expires.After(now) {
		return e.name
	}
	return ""
}

// Drain забирает накопленные запросы и счётчик выброшенных
func (p *Proxy) Drain() ([]agentapi.DNSQuery, uint64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	q, d := p.queue, p.dropped
	p.queue, p.dropped = nil, 0
	return q, d
}

// Requeue возвращает неотправленные запросы в очередь
func (p *Proxy) Requeue(q []agentapi.DNSQuery) {
	p.mu.Lock()
	defer p.mu.Unlock()
	room := p.maxQueued - len(p.queue)
	if room <= 0 {
		p.dropped += uint64(len(q))
		return
	}
	if len(q) > room {
		p.dropped += uint64(len(q) - room)
		q = q[len(q)-room:]
	}
	p.queue = append(q, p.queue...)
}

// Sweep удаляет просроченные соответствия
func (p *Proxy) Sweep() {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for src, m := range p.byPeer {
		for a, e := range m {
			if e.expires.Before(now) {
				delete(m, a)
			}
		}
		if len(m) == 0 {
			delete(p.byPeer, src)
		}
	}
	for a, e := range p.global {
		if e.expires.Before(now) {
			delete(p.global, a)
		}
	}
}

// addrOf извлекает IP из адреса UDP или TCP
func addrOf(a net.Addr) netip.Addr {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(v.IP)
		return ip.Unmap()
	}
	return netip.Addr{}
}
