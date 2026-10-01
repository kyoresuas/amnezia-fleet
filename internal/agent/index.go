package agent

import (
	"net/netip"
	"sync"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

type PeerIndex struct {
	mu       sync.RWMutex
	byKey    map[awg.Key]string
	byAddr   map[netip.Addr]string
	subnetV4 netip.Prefix
	subnetV6 netip.Prefix
	gateways map[netip.Addr]bool
}

// NewPeerIndex создаёт пустой индекс
func NewPeerIndex() *PeerIndex {
	return &PeerIndex{byKey: map[awg.Key]string{}, byAddr: map[netip.Addr]string{}, gateways: map[netip.Addr]bool{}}
}

// Update перестраивает индекс по желаемому состоянию
func (x *PeerIndex) Update(st agentapi.DesiredState) {
	byKey := make(map[awg.Key]string, len(st.Peers))
	byAddr := make(map[netip.Addr]string, len(st.Peers))
	for _, p := range st.Peers {
		byKey[p.PublicKey] = p.ID
		for _, a := range p.AllowedIPs {
			if a.IsSingleIP() {
				byAddr[a.Addr()] = p.ID
			}
		}
	}
	gateways := map[netip.Addr]bool{}
	if st.Interface.AddressV4.IsValid() {
		gateways[st.Interface.AddressV4.Addr()] = true
	}
	if st.Interface.AddressV6.IsValid() {
		gateways[st.Interface.AddressV6.Addr()] = true
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.byKey, x.byAddr, x.gateways = byKey, byAddr, gateways
	x.subnetV4, x.subnetV6 = st.Interface.AddressV4.Masked(), st.Interface.AddressV6.Masked()
}

// PeerByKey возвращает идентификатор пира по публичному ключу
func (x *PeerIndex) PeerByKey(k awg.Key) (string, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	id, ok := x.byKey[k]
	return id, ok
}

// PeerByAddr возвращает идентификатор пира по адресу в туннеле
func (x *PeerIndex) PeerByAddr(a netip.Addr) (string, bool) {
	x.mu.RLock()
	defer x.mu.RUnlock()
	id, ok := x.byAddr[a.Unmap()]
	return id, ok
}

// InTunnel сообщает, принадлежит ли адрес подсети туннеля
func (x *PeerIndex) InTunnel(a netip.Addr) bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	a = a.Unmap()
	return (x.subnetV4.IsValid() && x.subnetV4.Contains(a)) || (x.subnetV6.IsValid() && x.subnetV6.Contains(a))
}

// IsGateway сообщает, что адрес, шлюз туннеля (сам узел)
func (x *PeerIndex) IsGateway(a netip.Addr) bool {
	x.mu.RLock()
	defer x.mu.RUnlock()
	return x.gateways[a.Unmap()]
}
