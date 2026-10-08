//go:build linux

// Package netsetup
package netsetup

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/vishvananda/netlink"
)

const linkType = "amneziawg"

// EnsureLink создаёт интерфейс, выставляет MTU и адреса и поднимает его
func EnsureLink(name string, mtu int, addrs []netip.Prefix) error {
	link, err := netlink.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		attrs := netlink.NewLinkAttrs()
		attrs.Name = name
		if err := netlink.LinkAdd(&netlink.GenericLink{LinkAttrs: attrs, LinkType: linkType}); err != nil {
			return fmt.Errorf("создание %s (модуль amneziawg загружен?): %w", name, err)
		}
		link, err = netlink.LinkByName(name)
	}
	if err != nil {
		return fmt.Errorf("поиск %s: %w", name, err)
	}
	if link.Type() != linkType {
		return fmt.Errorf("интерфейс %s уже существует и имеет тип %s", name, link.Type())
	}
	if mtu > 0 && link.Attrs().MTU != mtu {
		if err := netlink.LinkSetMTU(link, mtu); err != nil {
			return fmt.Errorf("MTU %s: %w", name, err)
		}
	}
	if err := syncAddrs(link, addrs); err != nil {
		return err
	}
	if link.Attrs().Flags&1 == 0 || link.Attrs().OperState == netlink.OperDown {
		if err := netlink.LinkSetUp(link); err != nil {
			return fmt.Errorf("поднятие %s: %w", name, err)
		}
	}
	return nil
}

// syncAddrs приводит адреса интерфейса к точному списку
func syncAddrs(link netlink.Link, want []netip.Prefix) error {
	cur, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("адреса %s: %w", link.Attrs().Name, err)
	}
	wanted := map[string]bool{}
	for _, p := range want {
		wanted[p.String()] = true
	}
	have := map[string]bool{}
	for _, a := range cur {
		if a.IP.IsLinkLocalUnicast() {
			continue
		}
		key := a.IPNet.String()
		have[key] = true
		if !wanted[key] {
			if err := netlink.AddrDel(link, &a); err != nil {
				return fmt.Errorf("удаление адреса %s: %w", key, err)
			}
		}
	}
	for _, p := range want {
		if have[p.String()] {
			continue
		}
		addr, err := netlink.ParseAddr(p.String())
		if err != nil {
			return err
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			return fmt.Errorf("адрес %s: %w", p, err)
		}
	}
	return nil
}

// DeleteLink снимает интерфейс, если он есть
func DeleteLink(name string) error {
	link, err := netlink.LinkByName(name)
	var notFound netlink.LinkNotFoundError
	if errors.As(err, &notFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return netlink.LinkDel(link)
}

// Sysctls включает форвардинг и учёт байтов в conntrack
func Sysctls(ipv6 bool) error {
	set := map[string]string{
		"net/ipv4/ip_forward":             "1",
		"net/netfilter/nf_conntrack_acct": "1",
	}
	if ipv6 {
		set["net/ipv6/conf/all/forwarding"] = "1"
	}
	var errs []error
	for key, val := range set {
		path := "/proc/sys/" + key
		cur, err := os.ReadFile(path)
		if err == nil && strings.TrimSpace(string(cur)) == val {
			continue
		}
		if err := os.WriteFile(path, []byte(val), 0o644); err != nil {
			errs = append(errs, fmt.Errorf("sysctl %s: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

type FirewallSpec struct {
	Iface    string
	SubnetV4 netip.Prefix
	SubnetV6 netip.Prefix
	// Gateway, адрес резолвера агента, сюда заворачивается весь DNS клиентов
	Gateway netip.Addr
	// BlockDoH отклоняет публичные DoH, чтобы браузеры откатились на DNS узла
	BlockDoH bool
}

const tableName = "amnezia_fleet"

// правила пересоздаются атомарно одной транзакцией nft
var rulesetTmpl = template.Must(template.New("nft").Parse(`table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
	set private4 {
		type ipv4_addr
		flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
	}
	set private6 {
		type ipv6_addr
		flags interval
		elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
	}
	set doh4 {
		type ipv4_addr
		elements = { 1.1.1.1, 1.0.0.1, 1.1.1.2, 1.0.0.2, 1.1.1.3, 1.0.0.3, 8.8.8.8, 8.8.4.4, 9.9.9.9, 149.112.112.112, 9.9.9.11, 149.112.112.11, 94.140.14.14, 94.140.15.15, 94.140.14.140, 94.140.14.141, 208.67.222.222, 208.67.220.220, 76.76.2.0, 76.76.10.0, 194.242.2.2, 185.228.168.9, 185.228.169.9 }
	}
{{- if .Gateway.IsValid}}
	chain dns {
		type nat hook prerouting priority dstnat; policy accept;
		iifname "{{.Iface}}" ip daddr != {{.Gateway}} udp dport 53 dnat ip to {{.Gateway}}
		iifname "{{.Iface}}" ip daddr != {{.Gateway}} tcp dport 53 dnat ip to {{.Gateway}}
	}
{{- end}}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname "{{.Iface}}" tcp flags syn tcp option maxseg size set rt mtu
		oifname "{{.Iface}}" tcp flags syn tcp option maxseg size set rt mtu
		iifname "{{.Iface}}" oifname "{{.Iface}}" drop
		iifname "{{.Iface}}" tcp dport 853 reject with tcp reset
{{- if .BlockDoH}}
		iifname "{{.Iface}}" ip daddr @doh4 tcp dport 443 reject with tcp reset
		iifname "{{.Iface}}" ip daddr @doh4 udp dport 443 reject
{{- end}}
		iifname "{{.Iface}}" ip daddr @private4 drop
		iifname "{{.Iface}}" ip6 daddr @private6 drop
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr {{.SubnetV4}} oifname != "{{.Iface}}" masquerade
{{- if .SubnetV6.IsValid}}
		ip6 saddr {{.SubnetV6}} oifname != "{{.Iface}}" masquerade
{{- end}}
	}
}
`))

// ApplyFirewall применяет правила nftables и DOCKER-USER
func ApplyFirewall(spec FirewallSpec) error {
	var buf bytes.Buffer
	if err := rulesetTmpl.Execute(&buf, struct {
		FirewallSpec
		Table string
	}{spec, tableName}); err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return ensureDockerUser(spec.Iface)
}

// RemoveFirewall удаляет таблицу правил агента
func RemoveFirewall() error {
	out, err := exec.Command("nft", "delete", "table", "inet", tableName).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "No such file") {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureDockerUser добавляет разрешающие правила в цепочку DOCKER-USER
func ensureDockerUser(iface string) error {
	for _, bin := range []string{"iptables", "ip6tables"} {
		if _, err := exec.LookPath(bin); err != nil {
			continue
		}
		if exec.Command(bin, "-n", "-L", "DOCKER-USER").Run() != nil {
			continue
		}
		for _, dir := range []string{"-i", "-o"} {
			rule := []string{"DOCKER-USER", dir, iface, "-j", "ACCEPT", "-m", "comment", "--comment", "amnezia-fleet"}
			if exec.Command(bin, append([]string{"-C"}, rule...)...).Run() == nil {
				continue
			}
			if out, err := exec.Command(bin, append([]string{"-I"}, rule...)...).CombinedOutput(); err != nil {
				return fmt.Errorf("%s DOCKER-USER: %w: %s", bin, err, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}
