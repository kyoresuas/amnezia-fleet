// Package agentapi, протокол между fleetd, агентами и пробами
package agentapi

import (
	"net/netip"
	"time"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

const (
	PathState        = "/agent/v1/state"
	PathReport       = "/agent/v1/report"
	PathProbeTargets = "/probe/v1/targets"
	PathProbeResults = "/probe/v1/results"
)

// HeaderKnownRevision включает long-poll
const HeaderKnownRevision = "X-Fleet-Known-Revision"

type DesiredState struct {
	Revision  int64          `json:"revision"`
	ClusterID string         `json:"cluster_id"`
	NodeID    string         `json:"node_id"`
	Enabled   bool           `json:"enabled"`
	Interface InterfaceSpec  `json:"interface"`
	Peers     []PeerSpec     `json:"peers"`
	Telemetry TelemetryFlags `json:"telemetry"`
}

type InterfaceSpec struct {
	PrivateKey awg.Key      `json:"private_key"`
	ListenPort uint16       `json:"listen_port"`
	AddressV4  netip.Prefix `json:"address_v4"`
	AddressV6  netip.Prefix `json:"address_v6,omitzero"`
	MTU        int          `json:"mtu"`
	Params     awg.Params   `json:"params"`
}

type PeerSpec struct {
	ID           string         `json:"id,omitempty"`
	PublicKey    awg.Key        `json:"public_key"`
	PresharedKey awg.Key        `json:"preshared_key"`
	AllowedIPs   []netip.Prefix `json:"allowed_ips"`
}

type TelemetryFlags struct {
	Flows      bool `json:"flows"`
	DNSQueries bool `json:"dns_queries"`
}

type Report struct {
	AgentVersion    string       `json:"agent_version"`
	AppliedRevision int64        `json:"applied_revision"`
	LastError       string       `json:"last_error,omitempty"`
	CollectedAt     time.Time    `json:"collected_at"`
	Peers           []PeerStat   `json:"peers,omitempty"`
	Flows           []Flow       `json:"flows,omitempty"`
	DNSQueries      []DNSQuery   `json:"dns_queries,omitempty"`
	Usage           []PeerUsage  `json:"usage,omitempty"`
	Dropped         DroppedStats `json:"dropped"`
}

type PeerStat struct {
	PeerID        string         `json:"peer_id"`
	Endpoint      netip.AddrPort `json:"endpoint,omitzero"`
	LastHandshake *time.Time     `json:"last_handshake,omitempty"`
}

// PeerUsage: rx от клиента, tx к клиенту
type PeerUsage struct {
	PeerID string    `json:"peer_id"`
	From   time.Time `json:"from"`
	To     time.Time `json:"to"`
	Rx     uint64    `json:"rx"`
	Tx     uint64    `json:"tx"`
}

type Flow struct {
	Minute      time.Time  `json:"minute"`
	PeerID      string     `json:"peer_id"`
	Proto       uint8      `json:"proto"`
	DstIP       netip.Addr `json:"dst_ip"`
	DstPort     uint16     `json:"dst_port"`
	Domain      string     `json:"domain,omitempty"`
	BytesUp     uint64     `json:"bytes_up"`
	BytesDown   uint64     `json:"bytes_down"`
	PacketsUp   uint64     `json:"packets_up"`
	PacketsDown uint64     `json:"packets_down"`
	Connections uint32     `json:"connections"`
}

type DNSQuery struct {
	At      time.Time    `json:"at"`
	PeerID  string       `json:"peer_id"`
	Name    string       `json:"name"`
	Type    string       `json:"type"`
	RCode   string       `json:"rcode"`
	Answers []netip.Addr `json:"answers,omitempty"`
}

type DroppedStats struct {
	Flows      uint64 `json:"flows"`
	DNSQueries uint64 `json:"dns_queries"`
}

type ProbeTargets struct {
	Targets         []ProbeTarget `json:"targets"`
	IntervalSeconds int           `json:"interval_seconds"`
}

type ProbeTarget struct {
	AddressID       string         `json:"address_id"`
	ClusterID       string         `json:"cluster_id"`
	Endpoint        netip.AddrPort `json:"endpoint"`
	ServerPublicKey awg.Key        `json:"server_public_key"`
	Params          awg.Params     `json:"params"`
}

type ProbeResults struct {
	Results []ProbeResult `json:"results"`
}

type ProbeResult struct {
	AddressID string `json:"address_id"`
	OK        bool   `json:"ok"`
	RTTMs     *int   `json:"rtt_ms,omitempty"`
	Error     string `json:"error,omitempty"`
}
