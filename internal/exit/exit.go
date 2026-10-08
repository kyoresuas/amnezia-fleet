//go:build linux

// Package exit, сервер в другой стране для трафика выбранных доменов
package exit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/vishvananda/netlink"

	"github.com/kyoresuas/amnezia-fleet/internal/agentapi"
	"github.com/kyoresuas/amnezia-fleet/internal/awg"
)

const (
	tableName = "fleet_exit"
	mtu       = 1420
	syncEvery = 15 * time.Second
)

// Config, настройки выхода из окружения
type Config struct {
	ServerURL string
	Token     string
	Iface     string
}

// LoadConfig читает FLEET_SERVER_URL, FLEET_EXIT_TOKEN и FLEET_EXIT_IFACE
func LoadConfig() (Config, error) {
	c := Config{
		ServerURL: strings.TrimRight(os.Getenv("FLEET_SERVER_URL"), "/"),
		Token:     os.Getenv("FLEET_EXIT_TOKEN"),
		Iface:     os.Getenv("FLEET_EXIT_IFACE"),
	}
	if c.Iface == "" {
		c.Iface = "awgx0"
	}
	if c.ServerURL == "" || c.Token == "" {
		return c, errors.New("нужны FLEET_SERVER_URL и FLEET_EXIT_TOKEN")
	}
	return c, nil
}

// Exit держит устройство и синхронизирует пиров с control plane
type Exit struct {
	cfg        Config
	log        *slog.Logger
	http       *http.Client
	dev        *device.Device
	peers      map[awg.Key]netip.Addr
	forwardWas string
}

// New создаёт выход
func New(cfg Config, log *slog.Logger) *Exit {
	return &Exit{cfg: cfg, log: log, http: &http.Client{Timeout: 30 * time.Second}, peers: map[awg.Key]netip.Addr{}}
}

// Run поднимает интерфейс и работает до отмены контекста, затем всё за собой убирает
func (e *Exit) Run(ctx context.Context) error {
	st, err := e.waitState(ctx)
	if err != nil {
		return err
	}
	if err := e.up(st); err != nil {
		e.down()
		return err
	}
	defer e.down()
	e.log.Info("выход запущен", "iface", e.cfg.Iface, "port", st.ListenPort, "peers", len(st.Peers))
	t := time.NewTicker(syncEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		st, err := e.fetch(ctx)
		if err != nil {
			e.log.Warn("получение состояния", "err", err)
			continue
		}
		if err := e.syncPeers(st.Peers); err != nil {
			e.log.Error("синхронизация пиров", "err", err)
		}
	}
}

// waitState повторяет запрос состояния, пока control plane не ответит
func (e *Exit) waitState(ctx context.Context) (agentapi.ExitState, error) {
	for {
		st, err := e.fetch(ctx)
		if err == nil {
			return st, nil
		}
		e.log.Warn("ожидание control plane", "err", err)
		select {
		case <-ctx.Done():
			return st, ctx.Err()
		case <-time.After(10 * time.Second):
		}
	}
}

// fetch запрашивает состояние выхода
func (e *Exit) fetch(ctx context.Context) (agentapi.ExitState, error) {
	var st agentapi.ExitState
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.cfg.ServerURL+agentapi.PathExitState, nil)
	if err != nil {
		return st, err
	}
	req.Header.Set("Authorization", "Bearer "+e.cfg.Token)
	resp, err := e.http.Do(req)
	if err != nil {
		return st, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return st, fmt.Errorf("%d %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	err = json.NewDecoder(resp.Body).Decode(&st)
	return st, err
}

// up создаёт интерфейс, адрес, правила и включает форвардинг
func (e *Exit) up(st agentapi.ExitState) error {
	tdev, err := tun.CreateTUN(e.cfg.Iface, mtu)
	if err != nil {
		return fmt.Errorf("TUN %s: %w", e.cfg.Iface, err)
	}
	e.dev = device.NewDevice(tdev, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "exit: "))
	if err := e.dev.IpcSet(st.Params.UAPI(st.PrivateKey) + fmt.Sprintf("listen_port=%d\n", st.ListenPort)); err != nil {
		return fmt.Errorf("настройка устройства: %w", err)
	}
	if err := e.dev.Up(); err != nil {
		return err
	}
	link, err := netlink.LinkByName(e.cfg.Iface)
	if err != nil {
		return err
	}
	addr, err := netlink.ParseAddr(st.Address.String())
	if err != nil {
		return err
	}
	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("адрес: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	if err := e.firewall(st.Address.Masked()); err != nil {
		return err
	}
	if was, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward"); err == nil {
		e.forwardWas = strings.TrimSpace(string(was))
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
		return fmt.Errorf("ip_forward: %w", err)
	}
	return e.syncPeers(st.Peers)
}

// rules, своя таблица: наружу пускается только трафик из туннеля, остальной форвардинг закрыт
var rules = template.Must(template.New("nft").Parse(`table inet {{.Table}}
delete table inet {{.Table}}
table inet {{.Table}} {
	set private4 {
		type ipv4_addr
		flags interval
		elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
	}
	chain forward {
		type filter hook forward priority filter - 10; policy drop;
		ct state established,related accept
		iifname "{{.Iface}}" tcp flags syn tcp option maxseg size set rt mtu
		iifname "{{.Iface}}" ip daddr != @private4 accept
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr {{.Subnet}} oifname != "{{.Iface}}" masquerade
	}
}
`))

// firewall применяет правила одной транзакцией nft
func (e *Exit) firewall(subnet netip.Prefix) error {
	var buf bytes.Buffer
	if err := rules.Execute(&buf, map[string]any{"Table": tableName, "Iface": e.cfg.Iface, "Subnet": subnet}); err != nil {
		return err
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = &buf
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// syncPeers добавляет новых и удаляет лишних пиров, не трогая живые сессии
func (e *Exit) syncPeers(peers []agentapi.ExitPeer) error {
	want := make(map[awg.Key]netip.Addr, len(peers))
	for _, p := range peers {
		want[p.PublicKey] = p.Address
	}
	var b strings.Builder
	for k := range e.peers {
		if _, ok := want[k]; !ok {
			fmt.Fprintf(&b, "public_key=%s\nremove=true\n", k.Hex())
		}
	}
	for k, a := range want {
		if cur, ok := e.peers[k]; ok && cur == a {
			continue
		}
		fmt.Fprintf(&b, "public_key=%s\nreplace_allowed_ips=true\nallowed_ip=%s/32\n", k.Hex(), a)
	}
	if b.Len() == 0 {
		return nil
	}
	if err := e.dev.IpcSet(b.String()); err != nil {
		return err
	}
	e.peers = want
	e.log.Info("пиры обновлены", "count", len(want))
	return nil
}

// down закрывает устройство, удаляет правила и возвращает ip_forward
func (e *Exit) down() {
	if e.dev != nil {
		e.dev.Close()
	}
	_ = exec.Command("nft", "delete", "table", "inet", tableName).Run()
	if e.forwardWas != "" {
		_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(e.forwardWas), 0o644)
	}
}
