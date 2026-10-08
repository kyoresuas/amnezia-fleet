//go:build linux

// Package awgnl, клиент generic netlink модуля amneziawg
package awgnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"

	"github.com/mdlayher/genetlink"
	"github.com/mdlayher/netlink"

	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

// из src/uapi/wireguard.h модуля amneziawg
const (
	familyName       = "amneziawg"
	minFamilyVersion = 3

	cmdGetDevice = 0
	cmdSetDevice = 1

	deviceFReplacePeers = 1 << 0

	devAIfname                 = 2
	devAPrivateKey             = 3
	devAPublicKey              = 4
	devAFlags                  = 5
	devAListenPort             = 6
	devAFwmark                 = 7
	devAPeers                  = 8
	devAJc                     = 9
	devAJmin                   = 10
	devAJmax                   = 11
	devAS1                     = 12
	devAS2                     = 13
	devAH1                     = 14
	devAH2                     = 15
	devAH3                     = 16
	devAH4                     = 17
	devAS3                     = 19
	devAS4                     = 20
	devAHeaderProtectionKey    = 26
	devAContentPaddingAddition = 27
	devARekeyAfterTime         = 28
	devARekeyTimeout           = 29
	devARejectAfterTime        = 30
	devAKeepaliveTimeout       = 31
	devAMaxHandshakeAttempts   = 32
	devARandomTrailers         = 33
	devADisableCookies         = 34
	devAI1                     = 21

	peerFRemoveMe          = 1 << 0
	peerFReplaceAllowedIPs = 1 << 1

	peerAPublicKey     = 1
	peerAPresharedKey  = 2
	peerAFlags         = 3
	peerAEndpoint      = 4
	peerAKeepalive     = 5
	peerALastHandshake = 6
	peerARxBytes       = 7
	peerATxBytes       = 8
	peerAAllowedIPs    = 9

	aipAFamily   = 1
	aipAIPAddr   = 2
	aipACidrMask = 3

	afInet  = 2
	afInet6 = 10
)

const peersPerMessage = 64

type Client struct {
	conn   *genetlink.Conn
	family genetlink.Family
}

// Dial открывает соединение
func Dial() (*Client, error) {
	conn, err := genetlink.Dial(nil)
	if err != nil {
		return nil, fmt.Errorf("generic netlink: %w", err)
	}
	f, err := conn.GetFamily(familyName)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("семейство %s не найдено (модуль amneziawg загружен?): %w", familyName, err)
	}
	// до версии 3 другой формат H1-H4
	if f.Version < minFamilyVersion {
		conn.Close()
		return nil, fmt.Errorf("модуль amneziawg слишком старый: версия netlink %d, нужна %d (AmneziaWG 3.x)", f.Version, minFamilyVersion)
	}
	return &Client{conn: conn, family: f}, nil
}

// Close закрывает соединение
func (c *Client) Close() error {
	return c.conn.Close()
}

type Device struct {
	Name       string
	PrivateKey awg.Key
	PublicKey  awg.Key
	ListenPort uint16
	Params     awg.Params
	Peers      []Peer
}

type Peer struct {
	PublicKey     awg.Key
	PresharedKey  awg.Key
	Endpoint      netip.AddrPort
	LastHandshake time.Time
	RxBytes       uint64
	TxBytes       uint64
	AllowedIPs    []netip.Prefix
}

// Device читает состояние интерфейса
func (c *Client) Device(name string) (*Device, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(devAIfname, name)
	data, err := ae.Encode()
	if err != nil {
		return nil, err
	}
	msgs, err := c.conn.Execute(genetlink.Message{
		Header: genetlink.Header{Command: cmdGetDevice, Version: c.family.Version},
		Data:   data,
	}, c.family.ID, netlink.Request|netlink.Dump)
	if err != nil {
		if errors.Is(err, syscall.ENODEV) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("получение %s: %w", name, err)
	}
	d := &Device{}
	for _, m := range msgs {
		if err := parseDevice(d, m.Data); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// parseDevice разбирает одно сообщение дампа
func parseDevice(d *Device, b []byte) error {
	ad, err := netlink.NewAttributeDecoder(b)
	if err != nil {
		return err
	}
	for ad.Next() {
		switch ad.Type() {
		case devAIfname:
			d.Name = ad.String()
		case devAPrivateKey:
			copy(d.PrivateKey[:], ad.Bytes())
		case devAPublicKey:
			copy(d.PublicKey[:], ad.Bytes())
		case devAListenPort:
			d.ListenPort = ad.Uint16()
		case devAJc:
			d.Params.Jc = ad.Uint16()
		case devAJmin:
			d.Params.Jmin = ad.Uint16()
		case devAJmax:
			d.Params.Jmax = ad.Uint16()
		case devAS1:
			d.Params.S1 = ad.Uint16()
		case devAS2:
			d.Params.S2 = ad.Uint16()
		case devAS3:
			d.Params.S3 = ad.Uint16()
		case devAS4:
			d.Params.S4 = ad.Uint16()
		case devAH1:
			d.Params.H1 = awg.Range32FromNetlink(ad.Uint64())
		case devAH2:
			d.Params.H2 = awg.Range32FromNetlink(ad.Uint64())
		case devAH3:
			d.Params.H3 = awg.Range32FromNetlink(ad.Uint64())
		case devAH4:
			d.Params.H4 = awg.Range32FromNetlink(ad.Uint64())
		case devAHeaderProtectionKey:
			copy(d.Params.HeaderProtectionKey[:], ad.Bytes())
		case devAContentPaddingAddition:
			d.Params.ContentPaddingAddition = awg.Range16FromNetlink(ad.Uint32())
		case devARekeyAfterTime:
			d.Params.RekeyAfterTime = awg.Range16FromNetlink(ad.Uint32())
		case devARekeyTimeout:
			d.Params.RekeyTimeout = awg.Range16FromNetlink(ad.Uint32())
		case devARejectAfterTime:
			d.Params.RejectAfterTime = awg.Range16FromNetlink(ad.Uint32())
		case devAKeepaliveTimeout:
			d.Params.KeepaliveTimeout = awg.Range16FromNetlink(ad.Uint32())
		case devAMaxHandshakeAttempts:
			d.Params.MaxHandshakeAttempts = awg.Range16FromNetlink(ad.Uint32())
		case devARandomTrailers:
			d.Params.RandomTrailers = ad.Uint8() != 0
		case devADisableCookies:
			d.Params.DisableCookies = ad.Uint8() != 0
		case devAI1:
			d.Params.I1 = ad.String()
		case devAPeers:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					var p Peer
					nad.Nested(func(pad *netlink.AttributeDecoder) error {
						return parsePeer(&p, pad)
					})
					d.Peers = append(d.Peers, p)
				}
				return nil
			})
		}
	}
	return ad.Err()
}

// parsePeer разбирает атрибуты одного пира
func parsePeer(p *Peer, ad *netlink.AttributeDecoder) error {
	for ad.Next() {
		switch ad.Type() {
		case peerAPublicKey:
			copy(p.PublicKey[:], ad.Bytes())
		case peerAPresharedKey:
			copy(p.PresharedKey[:], ad.Bytes())
		case peerAEndpoint:
			p.Endpoint = parseSockaddr(ad.Bytes())
		case peerALastHandshake:
			b := ad.Bytes()
			if len(b) >= 16 {
				sec := int64(binary.NativeEndian.Uint64(b[0:8]))
				nsec := int64(binary.NativeEndian.Uint64(b[8:16]))
				if sec > 0 || nsec > 0 {
					p.LastHandshake = time.Unix(sec, nsec)
				}
			}
		case peerARxBytes:
			p.RxBytes = ad.Uint64()
		case peerATxBytes:
			p.TxBytes = ad.Uint64()
		case peerAAllowedIPs:
			ad.Nested(func(nad *netlink.AttributeDecoder) error {
				for nad.Next() {
					nad.Nested(func(aad *netlink.AttributeDecoder) error {
						var family uint16
						var ip []byte
						var bits uint8
						for aad.Next() {
							switch aad.Type() {
							case aipAFamily:
								family = aad.Uint16()
							case aipAIPAddr:
								ip = aad.Bytes()
							case aipACidrMask:
								bits = aad.Uint8()
							}
						}
						if addr, ok := netip.AddrFromSlice(ip); ok && (family == afInet || family == afInet6) {
							p.AllowedIPs = append(p.AllowedIPs, netip.PrefixFrom(addr.Unmap(), int(bits)))
						}
						return nil
					})
				}
				return nil
			})
		}
	}
	return nil
}

// parseSockaddr разбирает sockaddr_in или sockaddr_in6
func parseSockaddr(b []byte) netip.AddrPort {
	if len(b) < 2 {
		return netip.AddrPort{}
	}
	switch binary.NativeEndian.Uint16(b[0:2]) {
	case afInet:
		if len(b) >= 8 {
			addr, _ := netip.AddrFromSlice(b[4:8])
			return netip.AddrPortFrom(addr, binary.BigEndian.Uint16(b[2:4]))
		}
	case afInet6:
		if len(b) >= 24 {
			addr, _ := netip.AddrFromSlice(b[8:24])
			return netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(b[2:4]))
		}
	}
	return netip.AddrPort{}
}

type Config struct {
	PrivateKey   *awg.Key
	ListenPort   *uint16
	Params       *awg.Params
	ReplacePeers bool
	// Signatures передаёт I1-I5, нужны только стороне, которая начинает рукопожатие
	Signatures bool
	Peers      []PeerConfig
}

type PeerConfig struct {
	PublicKey         awg.Key
	PresharedKey      *awg.Key
	Remove            bool
	ReplaceAllowedIPs bool
	AllowedIPs        []netip.Prefix
	Endpoint          netip.AddrPort
	Keepalive         awg.Range16
}

// Configure применяет изменения
func (c *Client) Configure(name string, cfg Config) error {
	first := true
	peers := cfg.Peers
	for first || len(peers) > 0 {
		batch := peers
		if len(batch) > peersPerMessage {
			batch = batch[:peersPerMessage]
		}
		peers = peers[len(batch):]
		ae := netlink.NewAttributeEncoder()
		ae.String(devAIfname, name)
		if first {
			encodeDevice(ae, cfg)
		}
		if len(batch) > 0 {
			ae.Nested(devAPeers, func(nae *netlink.AttributeEncoder) error {
				for i, p := range batch {
					nae.Nested(uint16(i), func(pae *netlink.AttributeEncoder) error {
						encodePeer(pae, p)
						return nil
					})
				}
				return nil
			})
		}
		data, err := ae.Encode()
		if err != nil {
			return err
		}
		_, err = c.conn.Execute(genetlink.Message{
			Header: genetlink.Header{Command: cmdSetDevice, Version: c.family.Version},
			Data:   data,
		}, c.family.ID, netlink.Request|netlink.Acknowledge)
		if err != nil {
			return fmt.Errorf("настройка %s: %w", name, err)
		}
		first = false
	}
	return nil
}

// encodeDevice кодирует параметры устройства
func encodeDevice(ae *netlink.AttributeEncoder, cfg Config) {
	if cfg.PrivateKey != nil {
		ae.Bytes(devAPrivateKey, cfg.PrivateKey[:])
	}
	if cfg.ListenPort != nil {
		ae.Uint16(devAListenPort, *cfg.ListenPort)
	}
	if p := cfg.Params; p != nil {
		ae.Uint16(devAJc, p.Jc)
		ae.Uint16(devAJmin, p.Jmin)
		ae.Uint16(devAJmax, p.Jmax)
		ae.Uint16(devAS1, p.S1)
		ae.Uint16(devAS2, p.S2)
		ae.Uint16(devAS3, p.S3)
		ae.Uint16(devAS4, p.S4)
		ae.Uint64(devAH1, p.H1.Netlink())
		ae.Uint64(devAH2, p.H2.Netlink())
		ae.Uint64(devAH3, p.H3.Netlink())
		ae.Uint64(devAH4, p.H4.Netlink())
		if !p.HeaderProtectionKey.IsZero() {
			ae.Bytes(devAHeaderProtectionKey, p.HeaderProtectionKey[:])
		}
		ae.Uint32(devAContentPaddingAddition, p.ContentPaddingAddition.Netlink())
		ae.Uint32(devARekeyAfterTime, p.RekeyAfterTime.Netlink())
		ae.Uint32(devARekeyTimeout, p.RekeyTimeout.Netlink())
		ae.Uint32(devARejectAfterTime, p.RejectAfterTime.Netlink())
		ae.Uint32(devAKeepaliveTimeout, p.KeepaliveTimeout.Netlink())
		ae.Uint32(devAMaxHandshakeAttempts, p.MaxHandshakeAttempts.Netlink())
		ae.Uint8(devARandomTrailers, boolU8(p.RandomTrailers))
		ae.Uint8(devADisableCookies, boolU8(p.DisableCookies))
		if cfg.Signatures {
			for i, sig := range []string{p.I1, p.I2, p.I3, p.I4, p.I5} {
				if sig != "" {
					ae.String(uint16(devAI1+i), sig)
				}
			}
		}
	}
	if cfg.ReplacePeers {
		ae.Uint32(devAFlags, deviceFReplacePeers)
	}
}

// encodePeer кодирует один пир
func encodePeer(ae *netlink.AttributeEncoder, p PeerConfig) {
	ae.Bytes(peerAPublicKey, p.PublicKey[:])
	var flags uint32
	if p.Remove {
		flags |= peerFRemoveMe
		ae.Uint32(peerAFlags, flags)
		return
	}
	if p.ReplaceAllowedIPs {
		flags |= peerFReplaceAllowedIPs
	}
	if flags != 0 {
		ae.Uint32(peerAFlags, flags)
	}
	if p.PresharedKey != nil {
		ae.Bytes(peerAPresharedKey, p.PresharedKey[:])
	}
	if p.Endpoint.IsValid() {
		ae.Bytes(peerAEndpoint, sockaddr(p.Endpoint))
	}
	if !p.Keepalive.IsZero() {
		ae.Uint32(peerAKeepalive, p.Keepalive.Netlink())
	}
	if len(p.AllowedIPs) > 0 {
		ae.Nested(peerAAllowedIPs, func(nae *netlink.AttributeEncoder) error {
			for i, pfx := range p.AllowedIPs {
				nae.Nested(uint16(i), func(aae *netlink.AttributeEncoder) error {
					addr := pfx.Addr()
					if addr.Is4() {
						aae.Uint16(aipAFamily, afInet)
						a4 := addr.As4()
						aae.Bytes(aipAIPAddr, a4[:])
					} else {
						aae.Uint16(aipAFamily, afInet6)
						a16 := addr.As16()
						aae.Bytes(aipAIPAddr, a16[:])
					}
					aae.Uint8(aipACidrMask, uint8(pfx.Bits()))
					return nil
				})
			}
			return nil
		})
	}
}

// sockaddr кодирует адрес в sockaddr_in или sockaddr_in6, порт в сетевом порядке байт
func sockaddr(ap netip.AddrPort) []byte {
	addr := ap.Addr().Unmap()
	if addr.Is4() {
		b := make([]byte, 16)
		binary.NativeEndian.PutUint16(b[0:2], afInet)
		binary.BigEndian.PutUint16(b[2:4], ap.Port())
		a4 := addr.As4()
		copy(b[4:8], a4[:])
		return b
	}
	b := make([]byte, 28)
	binary.NativeEndian.PutUint16(b[0:2], afInet6)
	binary.BigEndian.PutUint16(b[2:4], ap.Port())
	a16 := addr.As16()
	copy(b[8:24], a16[:])
	return b
}

// boolU8 переводит bool в u8 атрибут
func boolU8(v bool) uint8 {
	if v {
		return 1
	}
	return 0
}

var ErrNotFound = errors.New("интерфейс не найден")
