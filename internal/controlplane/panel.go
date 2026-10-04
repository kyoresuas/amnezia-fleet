package controlplane

import (
	"embed"
	"fmt"
	"io/fs"
	"net/http"
	"path/filepath"

	"github.com/kyoresuas/amnezia-fleet/internal/store"
)

//go:embed panel
var panelFS embed.FS

// distFiles отдаются узлам при установке одной командой
var distFiles = map[string]string{
	"fleet-agent":         "application/octet-stream",
	"install-node.sh":     "text/x-shellscript",
	"fleet-agent.service": "text/plain",
}

// panelHandler отдаёт встроенную панель
func (s *Server) panelHandler() http.Handler {
	sub, err := fs.Sub(panelFS, "panel")
	if err != nil {
		panic(err)
	}
	files := http.StripPrefix("/panel/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; font-src 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		files.ServeHTTP(w, r)
	})
}

// serverURL восстанавливает внешний адрес fleetd за nginx
func serverURL(r *http.Request) string {
	scheme := "https"
	if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
		scheme = p
	}
	return scheme + "://" + r.Host
}

// installScript отдаёт скрипт установки узла, токен передаётся переменной окружения
func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	base := serverURL(r)
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	fmt.Fprintf(w, `#!/usr/bin/env bash
# Установка узла amnezia-fleet
# curl -fsSL %[1]s/install.sh | FLEET_AGENT_TOKEN=... bash
set -euo pipefail
: "${FLEET_AGENT_TOKEN:?задайте FLEET_AGENT_TOKEN}"
dir="$(mktemp -d)"
trap 'rm -rf "$dir"' EXIT
cd "$dir"
for f in fleet-agent install-node.sh fleet-agent.service; do
  curl -fsSL "%[1]s/dist/$f" -o "$f"
done
chmod +x fleet-agent install-node.sh
FLEET_SERVER_URL="%[1]s" ./install-node.sh ./fleet-agent
`, base)
}

// uninstallScript отдаёт скрипт удаления агента с узла
func (s *Server) uninstallScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	fmt.Fprint(w, `#!/usr/bin/env bash
# Удаление агента amnezia-fleet с узла
set -uo pipefail
iface="$(sed -n 's/^FLEET_IFACE=//p' /etc/fleet-agent.env 2>/dev/null)"
iface="${iface:-awgf0}"
systemctl disable --now fleet-agent 2>/dev/null
rm -f /etc/systemd/system/fleet-agent.service /etc/fleet-agent.env /usr/local/bin/fleet-agent
rm -rf /var/lib/fleet-agent
systemctl daemon-reload
ip link del "$iface" 2>/dev/null
nft delete table inet amnezia_fleet 2>/dev/null
for bin in iptables ip6tables; do
  for d in -i -o; do
    while $bin -D DOCKER-USER $d "$iface" -m comment --comment amnezia-fleet -j ACCEPT 2>/dev/null; do :; done
  done
done
echo "агент удалён, модуль amneziawg оставлен"
`)
}

// distFile отдаёт файлы для установки узла из FLEET_DIST_DIR
func (s *Server) distFile(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	ctype, ok := distFiles[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	http.ServeFile(w, r, filepath.Join(s.cfg.DistDir, name))
}

// listAllPeers возвращает все устройства, опционально одного кластера
func (s *Server) listAllPeers(w http.ResponseWriter, r *http.Request) {
	out, err := s.store.ListPeers(r.Context(), store.PeerFilter{ClusterID: r.URL.Query().Get("cluster_id")})
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, nonNil(out))
}

// peerQR отдаёт QR-код ссылки vpn:// в PNG
func (s *Server) peerQR(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.peerClientConfig(r)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	writeQR(w, cfg)
}

// meta отдаёт настройки, нужные панели для оценки состояния
func (s *Server) meta(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"node_stale_after_seconds": int(s.cfg.NodeStaleAfter.Seconds()),
		"probe_interval_seconds":   int(s.cfg.ProbeInterval.Seconds()),
		"dns_provider":             s.cfg.DNSProvider,
		"telemetry":                s.tele != nil,
	})
}

// redirectPanel ведёт корень сайта в панель
func redirectPanel(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, "/panel/", http.StatusFound)
}
