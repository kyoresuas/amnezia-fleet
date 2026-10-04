// Package model
package model

import (
	"net/netip"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

type DNSMode string

const (
	// один адрес, остальные в резерве
	DNSModeFailover DNSMode = "failover"
	DNSModeAll      DNSMode = "all"
)

// Cluster, логический сервер на нескольких узлах
type Cluster struct {
	ID         string       `json:"id"`
	Name       string       `json:"name"`
	Hostname   string       `json:"hostname"`
	ListenPort uint16       `json:"listen_port"`
	PublicKey  awg.Key      `json:"public_key"`
	PrivateKey awg.Key      `json:"-"`
	Params     awg.Params   `json:"params"`
	SubnetV4   netip.Prefix `json:"subnet_v4"`
	SubnetV6   netip.Prefix `json:"subnet_v6,omitzero"`
	DNS        []string     `json:"dns"`
	MTU        int          `json:"mtu"`
	DNSMode    DNSMode      `json:"dns_mode"`
	DNSTTL     int          `json:"dns_ttl"`
	Revision   int64        `json:"revision"`
	CreatedAt  time.Time    `json:"created_at"`
	UpdatedAt  time.Time    `json:"updated_at"`
}

// GatewayV4 возвращает адрес узла внутри туннеля (первый адрес подсети)
func (c Cluster) GatewayV4() netip.Addr {
	return c.SubnetV4.Masked().Addr().Next()
}

// GatewayV6 возвращает IPv6-адрес узла внутри туннеля, если IPv6 включён
func (c Cluster) GatewayV6() netip.Addr {
	if !c.SubnetV6.IsValid() {
		return netip.Addr{}
	}
	return c.SubnetV6.Masked().Addr().Next()
}

type NodeState string

const (
	NodeActive   NodeState = "active"
	NodeDraining NodeState = "draining"
	NodeDisabled NodeState = "disabled"
)

type Node struct {
	ID              string     `json:"id"`
	ClusterID       string     `json:"cluster_id"`
	Name            string     `json:"name"`
	State           NodeState  `json:"state"`
	LastSeenAt      *time.Time `json:"last_seen_at,omitempty"`
	AgentVersion    string     `json:"agent_version,omitempty"`
	AppliedRevision int64      `json:"applied_revision"`
	LastError       string     `json:"last_error,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	Addresses       []Address  `json:"addresses"`
}

type AddressState string

const (
	AddressActive AddressState = "active"
	// в DNS, только если активных не осталось
	AddressSpare    AddressState = "spare"
	AddressBlocked  AddressState = "blocked"
	AddressDisabled AddressState = "disabled"
)

type Address struct {
	ID              string       `json:"id"`
	NodeID          string       `json:"node_id"`
	IP              netip.Addr   `json:"ip"`
	State           AddressState `json:"state"`
	Priority        int          `json:"priority"`
	Health          string       `json:"health"`
	HealthChangedAt *time.Time   `json:"health_changed_at,omitempty"`
	CreatedAt       time.Time    `json:"created_at"`
}

type UserStatus string

const (
	UserActive    UserStatus = "active"
	UserSuspended UserStatus = "suspended"
)

type User struct {
	ID                string     `json:"id"`
	Name              string     `json:"name"`
	Note              string     `json:"note,omitempty"`
	Status            UserStatus `json:"status"`
	TrafficLimitBytes *int64     `json:"traffic_limit_bytes,omitempty"`
	ExpiresAt         *time.Time `json:"expires_at,omitempty"`
	DeviceLimit       *int       `json:"device_limit,omitempty"`
	HasLink           bool       `json:"has_link"`
	CreatedAt         time.Time  `json:"created_at"`
}

type Peer struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	ClusterID    string     `json:"cluster_id"`
	Name         string     `json:"name"`
	PublicKey    awg.Key    `json:"public_key"`
	PrivateKey   awg.Key    `json:"-"`
	PresharedKey awg.Key    `json:"-"`
	AddressV4    netip.Addr `json:"address_v4"`
	AddressV6    netip.Addr `json:"address_v6,omitzero"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
}

type Probe struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Region     string     `json:"region"`
	PublicKey  awg.Key    `json:"public_key"`
	LastSeenAt *time.Time `json:"last_seen_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}
