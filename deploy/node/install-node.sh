#!/usr/bin/env bash
# Установка узла: модуль amneziawg, nftables, агент
# FLEET_SERVER_URL=https://fleet.example.com FLEET_AGENT_TOKEN=... ./install-node.sh /path/to/fleet-agent
set -euo pipefail

AGENT_BIN="${1:-./fleet-agent}"
: "${FLEET_SERVER_URL:?задайте FLEET_SERVER_URL}"
: "${FLEET_AGENT_TOKEN:?задайте FLEET_AGENT_TOKEN}"
FLEET_IFACE="${FLEET_IFACE:-awgf0}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [[ $EUID -ne 0 ]]; then
  echo "запустите от root" >&2
  exit 1
fi
if [[ ! -x "$AGENT_BIN" ]]; then
  echo "бинарник агента не найден: $AGENT_BIN" >&2
  exit 1
fi

# DKMS нужны исходники ядра из deb-src
enable_deb_src() {
  if [[ -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
    if ! grep -q '^Types:.*deb-src' /etc/apt/sources.list.d/ubuntu.sources; then
      sed -i 's/^Types: deb$/Types: deb deb-src/' /etc/apt/sources.list.d/ubuntu.sources
    fi
  elif [[ -f /etc/apt/sources.list ]]; then
    sed -i 's/^# *deb-src/deb-src/' /etc/apt/sources.list
  fi
}

install_module() {
  if modprobe -n amneziawg 2>/dev/null && [[ -n "$(modinfo -F version amneziawg 2>/dev/null)" ]]; then
    echo "модуль amneziawg уже установлен: $(modinfo -F version amneziawg)"
    return
  fi
  export DEBIAN_FRONTEND=noninteractive
  enable_deb_src
  apt-get update
  apt-get install -y software-properties-common python3-launchpadlib gnupg2 "linux-headers-$(uname -r)"
  add-apt-repository -y ppa:amnezia/ppa
  apt-get update
  apt-get install -y amneziawg
}

install_module
apt-get install -y nftables >/dev/null
modprobe amneziawg
echo "amneziawg" > /etc/modules-load.d/amneziawg.conf

install -m 0755 "$AGENT_BIN" /usr/local/bin/fleet-agent
umask 077
cat > /etc/fleet-agent.env <<EOF
FLEET_SERVER_URL=${FLEET_SERVER_URL}
FLEET_AGENT_TOKEN=${FLEET_AGENT_TOKEN}
FLEET_IFACE=${FLEET_IFACE}
EOF
install -m 0644 "$SCRIPT_DIR/fleet-agent.service" /etc/systemd/system/fleet-agent.service
systemctl daemon-reload
systemctl enable --now fleet-agent
sleep 3
systemctl --no-pager --lines=20 status fleet-agent || true
