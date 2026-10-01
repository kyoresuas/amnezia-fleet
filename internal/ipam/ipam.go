// Package ipam
package ipam

import (
	"errors"
	"math/big"
	"net/netip"
)

var ErrExhausted = errors.New("в подсети нет свободных адресов")

// NextFreeV4 возвращает первый свободный адрес подсети, пропуская адрес сети
func NextFreeV4(subnet netip.Prefix, used map[netip.Addr]bool) (netip.Addr, error) {
	subnet = subnet.Masked()
	gateway := subnet.Addr().Next()
	for a := gateway.Next(); subnet.Contains(a); a = a.Next() {
		if !subnet.Contains(a.Next()) {
			// последний адрес, broadcast
			break
		}
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}

// MapToV6 даёт IPv6 с тем же смещением в подсети, что у IPv4
func MapToV6(subnet4 netip.Prefix, addr4 netip.Addr, subnet6 netip.Prefix) (netip.Addr, error) {
	if !subnet6.IsValid() {
		return netip.Addr{}, nil
	}
	base4 := subnet4.Masked().Addr().As4()
	a4 := addr4.As4()
	offset := new(big.Int).Sub(new(big.Int).SetBytes(a4[:]), new(big.Int).SetBytes(base4[:]))
	base6 := subnet6.Masked().Addr().As16()
	sum := new(big.Int).Add(new(big.Int).SetBytes(base6[:]), offset)
	raw := sum.Bytes()
	if len(raw) > 16 {
		return netip.Addr{}, ErrExhausted
	}
	var out [16]byte
	copy(out[16-len(raw):], raw)
	addr6 := netip.AddrFrom16(out)
	if !subnet6.Contains(addr6) {
		return netip.Addr{}, ErrExhausted
	}
	return addr6, nil
}
