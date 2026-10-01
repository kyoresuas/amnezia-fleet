// Package failover, выбор адресов для DNS
package failover

import (
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/model"
)

const (
	HealthUp      = "up"
	HealthDown    = "down"
	HealthUnknown = "unknown"
)

type ProbeView struct {
	OK     bool
	Streak int
}

// AggregateHealth сводит результаты наблюдателей в одно значение
func AggregateHealth(views []ProbeView, failThreshold int) string {
	if len(views) == 0 {
		return HealthUnknown
	}
	allDown := true
	for _, v := range views {
		if v.OK {
			return HealthUp
		}
		if v.Streak < failThreshold {
			allDown = false
		}
	}
	if allDown {
		return HealthDown
	}
	return HealthUnknown
}

type Candidate struct {
	Address   model.Address
	NodeState model.NodeState
	NodeAlive bool
}

// eligible сообщает, можно ли вообще публиковать адрес
func (c Candidate) eligible() bool {
	if c.NodeState != model.NodeActive || !c.NodeAlive {
		return false
	}
	if c.Address.State != model.AddressActive && c.Address.State != model.AddressSpare {
		return false
	}
	return c.Address.Health != HealthDown
}

// rank возвращает ключ сортировки: меньше, лучше
func (c Candidate) rank() [3]int {
	state := 0
	if c.Address.State == model.AddressSpare {
		state = 1
	}
	health := 0
	if c.Address.Health != HealthUp {
		health = 1
	}
	return [3]int{state, health, c.Address.Priority}
}

type Decision struct {
	Records []netip.Addr
	Kept    bool
}

// Select выбирает записи для одного семейства (A или AAAA)
func Select(mode model.DNSMode, candidates []Candidate, current []netip.Addr, is4 bool) Decision {
	var pool []Candidate
	for _, c := range candidates {
		if c.Address.IP.Is4() == is4 && c.eligible() {
			pool = append(pool, c)
		}
	}
	var cur []netip.Addr
	for _, a := range current {
		if a.Is4() == is4 {
			cur = append(cur, a)
		}
	}
	if len(pool) == 0 {
		return Decision{Records: cur, Kept: true}
	}
	sort.SliceStable(pool, func(i, j int) bool {
		ri, rj := pool[i].rank(), pool[j].rank()
		if ri != rj {
			return slices.Compare(ri[:], rj[:]) < 0
		}
		return pool[i].Address.IP.Less(pool[j].Address.IP)
	})

	if mode == model.DNSModeAll {
		var up []netip.Addr
		var all []netip.Addr
		for _, c := range pool {
			all = append(all, c.Address.IP)
			if c.Address.Health == HealthUp {
				up = append(up, c.Address.IP)
			}
		}
		if len(up) > 0 {
			return Decision{Records: up}
		}
		return Decision{Records: all}
	}

	for _, a := range cur {
		for _, c := range pool {
			if c.Address.IP == a {
				return Decision{Records: []netip.Addr{a}}
			}
		}
	}
	return Decision{Records: []netip.Addr{pool[0].Address.IP}}
}

// NodeAlive сообщает, присылал ли агент heartbeat недавно
func NodeAlive(n model.Node, staleAfter time.Duration, now time.Time) bool {
	return n.LastSeenAt != nil && now.Sub(*n.LastSeenAt) < staleAfter
}
