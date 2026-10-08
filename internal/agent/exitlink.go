//go:build linux

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/kyoresuas/amnezia-fleet/internal/agent/awgnl"
	"github.com/kyoresuas/amnezia-fleet/internal/agent/netsetup"
	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

const (
	exitIface     = "awgx0"
	exitMTU       = 1420
	exitTable     = 51820
	exitMark      = 0x5958
	exitRulePrio  = 1000
	exitNftTable  = "amnezia_fleet_exit"
	exitSetTTL    = "6h"
	exitStaleness = 3 * time.Minute
)

// exitKeepalive держит NAT до выхода открытым
var exitKeepalive = awg.Range16{Lo: 25, Hi: 25}

// applyExit поднимает или убирает туннель до выхода
func (a *Agent) applyExit(spec *agentapi.ExitSpec, clientIface string) error {
	if spec == nil {
		a.dns.SetExit(nil, netip.Addr{}, nil)
		return teardownExit()
	}
	if err := netsetup.EnsureLink(exitIface, exitMTU, []netip.Prefix{netip.PrefixFrom(spec.Address, 32)}); err != nil {
		return err
	}
	nl, err := a.netlink()
	if err != nil {
		return err
	}
	dev, err := nl.Device(exitIface)
	if err != nil {
		a.resetNetlink()
		return err
	}
	if cfg, changed := diffExit(dev, spec); changed {
		if err := nl.Configure(exitIface, cfg); err != nil {
			a.resetNetlink()
			return err
		}
	}
	if err := exitRouting(spec.DNS); err != nil {
		return err
	}
	if err := exitFirewall(clientIface); err != nil {
		return err
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/conf/"+exitIface+"/rp_filter", []byte("2"), 0o644)
	a.dns.SetExit(spec.Domains, spec.DNS, addExitIPs)
	return nil
}

// diffExit сравнивает интерфейс с желаемым и возвращает полную конфигурацию, если что-то отличается
func diffExit(dev *awgnl.Device, spec *agentapi.ExitSpec) (awgnl.Config, bool) {
	params := spec.Params
	params.PersistentKeepalive = awg.Range16{}
	params.I1, params.I2, params.I3, params.I4, params.I5 = "", "", "", "", ""
	cur := dev.Params
	cur.PersistentKeepalive = awg.Range16{}
	cur.I1, cur.I2, cur.I3, cur.I4, cur.I5 = "", "", "", "", ""
	all := netip.MustParsePrefix("0.0.0.0/0")
	same := dev.PrivateKey == spec.PrivateKey && cur == params && len(dev.Peers) == 1 &&
		dev.Peers[0].PublicKey == spec.ServerPublicKey && dev.Peers[0].Endpoint == spec.Endpoint &&
		len(dev.Peers[0].AllowedIPs) == 1 && dev.Peers[0].AllowedIPs[0] == all
	if same {
		return awgnl.Config{}, false
	}
	key := spec.PrivateKey
	p := spec.Params
	return awgnl.Config{
		PrivateKey:   &key,
		Params:       &p,
		Signatures:   true,
		ReplacePeers: true,
		Peers: []awgnl.PeerConfig{{
			PublicKey:  spec.ServerPublicKey,
			Endpoint:   spec.Endpoint,
			Keepalive:  exitKeepalive,
			AllowedIPs: []netip.Prefix{all},
		}},
	}, true
}

// exitRouting направляет помеченный трафик и запросы к DNS выхода в отдельную таблицу
func exitRouting(dns netip.Addr) error {
	link, err := netlink.LinkByName(exitIface)
	if err != nil {
		return err
	}
	_, any4, _ := net.ParseCIDR("0.0.0.0/0")
	if err := netlink.RouteReplace(&netlink.Route{LinkIndex: link.Attrs().Index, Dst: any4, Table: exitTable, Scope: netlink.SCOPE_LINK}); err != nil {
		return fmt.Errorf("маршрут выхода: %w", err)
	}
	mark := netlink.NewRule()
	mark.Priority = exitRulePrio
	mark.Mark = exitMark
	mark.Table = exitTable
	toDNS := netlink.NewRule()
	toDNS.Priority = exitRulePrio + 1
	toDNS.Dst = &net.IPNet{IP: dns.AsSlice(), Mask: net.CIDRMask(32, 32)}
	toDNS.Table = exitTable
	rules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, want := range []*netlink.Rule{mark, toDNS} {
		found := false
		for _, r := range rules {
			if r.Priority != want.Priority {
				continue
			}
			if r.Table == want.Table && r.Mark == want.Mark && ipNetEqual(r.Dst, want.Dst) {
				found = true
				continue
			}
			// правило с нашим приоритетом, но другое (например, сменился DNS), убираем
			_ = netlink.RuleDel(&r)
		}
		if !found {
			if err := netlink.RuleAdd(want); err != nil {
				return fmt.Errorf("правило маршрутизации: %w", err)
			}
		}
	}
	return nil
}

// ipNetEqual сравнивает подсети, nil равен только nil
func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.String() == b.String()
}

// exitFirewall создаёт набор адресов и метку, таблица не пересоздаётся, набор не теряется
func exitFirewall(clientIface string) error {
	script := fmt.Sprintf(`add table inet %[1]s
add set inet %[1]s exit4 { type ipv4_addr; flags timeout; }
add chain inet %[1]s prerouting { type filter hook prerouting priority mangle; policy accept; }
flush chain inet %[1]s prerouting
add rule inet %[1]s prerouting iifname "%[2]s" ip daddr @exit4 meta mark set %[3]d
`, exitNftTable, clientIface, exitMark)
	return nft(script)
}

// addExitIPs добавляет адреса в набор, их трафик уйдёт через выход
func addExitIPs(ips []netip.Addr) error {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip.Is4() {
			parts = append(parts, ip.String()+" timeout "+exitSetTTL)
		}
	}
	if len(parts) == 0 {
		return nil
	}
	return nft(fmt.Sprintf("add element inet %s exit4 { %s }\n", exitNftTable, strings.Join(parts, ", ")))
}

// flushExitIPs очищает набор, трафик идёт напрямую
func flushExitIPs() {
	_ = nft(fmt.Sprintf("flush set inet %s exit4\n", exitNftTable))
}

// nft применяет команды одной транзакцией
func nft(script string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = bytes.NewBufferString(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// teardownExit убирает интерфейс, правила и таблицу выхода
func teardownExit() error {
	var errs []error
	if rules, err := netlink.RuleList(netlink.FAMILY_V4); err == nil {
		for _, r := range rules {
			if r.Table == exitTable && (r.Priority == exitRulePrio || r.Priority == exitRulePrio+1) {
				_ = netlink.RuleDel(&r)
			}
		}
	}
	_ = exec.Command("nft", "delete", "table", "inet", exitNftTable).Run()
	errs = append(errs, netsetup.DeleteLink(exitIface))
	return errors.Join(errs...)
}

// checkExit выключает маршрут через выход, если рукопожатия давно не было, и включает обратно
func (a *Agent) checkExit(now time.Time) {
	a.mu.Lock()
	hasExit := a.state != nil && a.state.Exit != nil
	a.mu.Unlock()
	if !hasExit {
		return
	}
	nl, err := a.netlink()
	if err != nil {
		return
	}
	dev, err := nl.Device(exitIface)
	if err != nil || len(dev.Peers) == 0 {
		return
	}
	alive := !dev.Peers[0].LastHandshake.IsZero() && now.Sub(dev.Peers[0].LastHandshake) < exitStaleness
	a.mu.Lock()
	changed := a.exitAlive != alive
	a.exitAlive = alive
	a.mu.Unlock()
	a.dns.SetExitActive(alive)
	if !changed {
		return
	}
	if alive {
		a.log.Info("выход доступен, домены идут через него")
		return
	}
	flushExitIPs()
	a.log.Warn("выход недоступен, домены идут напрямую")
}
