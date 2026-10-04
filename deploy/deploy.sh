#!/usr/bin/env bash
# Деплой по inventory.env: control plane, сертификат, кластер, узлы, проба
# ./deploy/deploy.sh [all|control|cert|cluster|nodes|probe]
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/.." && pwd)"
INVENTORY="${FLEET_INVENTORY:-$DIR/inventory.env}"
STATE="$DIR/state.env"
KEY="${FLEET_SSH_KEY:-$HOME/.ssh/amnezia_fleet}"
BIN="$ROOT/bin/linux"

# shellcheck source=/dev/null
source "$INVENTORY"
SSH_USER="${SSH_USER:-root}"
CF_API_TOKEN="${CF_API_TOKEN:-}"
CF_ZONE_ID="${CF_ZONE_ID:-}"
SSH_OPTS=(-i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 -o StrictHostKeyChecking=accept-new)

# rsh выполняет команду на хосте
rsh() {
  local host="$1"
  shift
  ssh "${SSH_OPTS[@]}" "$SSH_USER@$host" "$@"
}

# rcp копирует файлы на хост в указанный каталог
rcp() {
  local host="$1" dest="$2"
  shift 2
  scp -q "${SSH_OPTS[@]}" "$@" "$SSH_USER@$host:$dest"
}

# log печатает заголовок шага
log() {
  printf '\n== %s\n' "$*"
}

# build собирает бинарники под linux/amd64
build() {
  log "сборка"
  mkdir -p "$BIN"
  (
    cd "$ROOT"
    for cmd in fleetd fleet-agent fleet-probe; do
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local go build -trimpath -ldflags "-s -w" -o "$BIN/$cmd" "./cmd/$cmd"
    done
  )
}

# api вызывает API fleetd в обход DNS, напрямую на CONTROL_HOST
api() {
  local path="$1"
  shift
  curl -sS --fail-with-body --resolve "$API_DOMAIN:443:$CONTROL_HOST" \
    -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
    "https://$API_DOMAIN/api/v1$path" "$@"
}

# jq_py достаёт значение из JSON выражением Python над переменной d
jq_py() {
  python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"
}

# load_token читает админский токен с control plane и кеширует его локально
load_token() {
  if [[ -f "$STATE" ]]; then
    # shellcheck source=/dev/null
    source "$STATE"
  fi
  if [[ -z "${ADMIN_TOKEN:-}" ]]; then
    ADMIN_TOKEN="$(rsh "$CONTROL_HOST" "sed -n 's/^FLEET_ADMIN_TOKEN=//p' /etc/fleetd/fleetd.env")"
    umask 077
    echo "ADMIN_TOKEN=$ADMIN_TOKEN" >"$STATE"
  fi
}

# deploy_control ставит Postgres и ClickHouse в Docker на 127.0.0.1 и fleetd как systemd-сервис
deploy_control() {
  log "control plane на $CONTROL_HOST"
  rcp "$CONTROL_HOST" /tmp/ "$BIN/fleetd"
  rsh "$CONTROL_HOST" "install -d -m 755 /usr/local/share/fleetd"
  rcp "$CONTROL_HOST" /usr/local/share/fleetd/ "$BIN/fleet-agent" "$ROOT/deploy/node/install-node.sh" "$ROOT/deploy/node/fleet-agent.service"
  rsh "$CONTROL_HOST" "CF_API_TOKEN='$CF_API_TOKEN' CF_ZONE_ID='$CF_ZONE_ID' bash -s" <<'REMOTE'
set -euo pipefail
install -d -m 700 /etc/fleetd
if [[ ! -f /etc/fleetd/fleetd.env ]]; then
  umask 077
  PG_PASSWORD=$(openssl rand -hex 16)
  CH_PASSWORD=$(openssl rand -hex 16)
  cat >/etc/fleetd/fleetd.env <<EOF
PG_PASSWORD=$PG_PASSWORD
CH_PASSWORD=$CH_PASSWORD
FLEET_LISTEN=127.0.0.1:18080
FLEET_DATABASE_URL=postgres://fleet:$PG_PASSWORD@127.0.0.1:15432/fleet?sslmode=disable
FLEET_CLICKHOUSE_URL=http://fleet:$CH_PASSWORD@127.0.0.1:18123/fleet
FLEET_MASTER_KEY=$(openssl rand -base64 32)
FLEET_ADMIN_TOKEN=$(openssl rand -hex 32)
EOF
  echo "секреты созданы в /etc/fleetd/fleetd.env"
fi
# shellcheck source=/dev/null
source /etc/fleetd/fleetd.env

umask 077
if [[ -n "$CF_API_TOKEN" && -n "$CF_ZONE_ID" ]]; then
  printf 'FLEET_DNS_PROVIDER=cloudflare\nFLEET_CLOUDFLARE_API_TOKEN=%s\nFLEET_CLOUDFLARE_ZONE_ID=%s\n' "$CF_API_TOKEN" "$CF_ZONE_ID" >/etc/fleetd/dns.env
else
  printf 'FLEET_DNS_PROVIDER=none\n' >/etc/fleetd/dns.env
fi

if ! docker inspect fleet-pg >/dev/null 2>&1; then
  docker run -d --name fleet-pg --restart unless-stopped -p 127.0.0.1:15432:5432 \
    -e POSTGRES_DB=fleet -e POSTGRES_USER=fleet -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -v fleet-pg-data:/var/lib/postgresql/data postgres:17-alpine >/dev/null
fi
if ! docker inspect fleet-ch >/dev/null 2>&1; then
  docker run -d --name fleet-ch --restart unless-stopped -p 127.0.0.1:18123:8123 \
    --ulimit nofile=262144:262144 \
    -e CLICKHOUSE_DB=fleet -e CLICKHOUSE_USER=fleet -e CLICKHOUSE_PASSWORD="$CH_PASSWORD" \
    -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=0 \
    -v fleet-ch-data:/var/lib/clickhouse clickhouse/clickhouse-server:25.8-alpine >/dev/null
fi
for _ in $(seq 1 60); do
  docker exec fleet-pg pg_isready -U fleet -d fleet >/dev/null 2>&1 && curl -sf http://127.0.0.1:18123/ping >/dev/null && break
  sleep 2
done

install -m 0755 /tmp/fleetd /usr/local/bin/fleetd
rm -f /tmp/fleetd
cat >/etc/systemd/system/fleetd.service <<'EOF'
[Unit]
Description=amnezia-fleet control plane
After=network-online.target docker.service
Wants=network-online.target

[Service]
EnvironmentFile=/etc/fleetd/fleetd.env
EnvironmentFile=/etc/fleetd/dns.env
ExecStart=/usr/local/bin/fleetd
Restart=always
RestartSec=5
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable fleetd >/dev/null 2>&1
systemctl restart fleetd
for _ in $(seq 1 30); do
  curl -sf http://127.0.0.1:18080/healthz >/dev/null && break
  sleep 2
done
curl -sf http://127.0.0.1:18080/healthz && echo
REMOTE
}

# deploy_cert добавляет vhost в nginx и выпускает сертификат существующим аккаунтом certbot
deploy_cert() {
  log "nginx и сертификат для $API_DOMAIN"
  rsh "$CONTROL_HOST" "DOMAIN='$API_DOMAIN' bash -s" <<'REMOTE'
set -euo pipefail
conf="/etc/nginx/sites-available/$DOMAIN.conf"
if [[ ! -f "$conf" ]]; then
  cat >"$conf" <<EOF
server {
  listen 80;
  server_name $DOMAIN;
  client_max_body_size 32m;

  location / {
    proxy_pass http://127.0.0.1:18080;
    proxy_http_version 1.1;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    proxy_read_timeout 90s;
    proxy_buffering off;
  }
}
EOF
  ln -sf "$conf" "/etc/nginx/sites-enabled/$DOMAIN.conf"
fi
nginx -t
systemctl reload nginx
if [[ ! -d "/etc/letsencrypt/live/$DOMAIN" ]]; then
  certbot --nginx -d "$DOMAIN" --non-interactive --redirect
fi
nginx -t && systemctl reload nginx
REMOTE
  load_token
  curl -sS --resolve "$API_DOMAIN:443:$CONTROL_HOST" "https://$API_DOMAIN/healthz" && echo
}

# deploy_cluster создаёт кластер и узлы, если их ещё нет
deploy_cluster() {
  log "кластер $CLUSTER_NAME"
  load_token
  CLUSTER_ID="$(api /clusters | jq_py "next((c['id'] for c in d if c['name']=='$CLUSTER_NAME'), '')")"
  if [[ -z "$CLUSTER_ID" ]]; then
    CLUSTER_ID="$(api /clusters -X POST -d "{\"name\":\"$CLUSTER_NAME\",\"hostname\":\"$VPN_DOMAIN\"}" | jq_py "d['id']")"
    echo "кластер создан: $CLUSTER_ID"
  else
    echo "кластер уже есть: $CLUSTER_ID"
  fi
}

# node_fields разбирает строку узла в name, host и ips
node_fields() {
  read -r name host ips <<<"$1"
  ips="${ips:-$host}"
}

# deploy_nodes регистрирует узлы и ставит на них агента; недоступные узлы пропускаются
deploy_nodes() {
  deploy_cluster
  local nodes
  nodes="$(api "/clusters/$CLUSTER_ID/nodes")"
  for line in "${NODES[@]}"; do
    node_fields "$line"
    log "узел $name ($host)"
    if ! rsh "$host" true 2>/dev/null; then
      echo "нет SSH-доступа, пропускаю"
      continue
    fi
    local id token
    id="$(echo "$nodes" | jq_py "next((n['id'] for n in d if n['name']=='$name'), '')")"
    if [[ -z "$id" ]]; then
      local addrs
      addrs="$(python3 -c "import json,sys; print(json.dumps(sys.argv[1].split(',')))" "$ips")"
      token="$(api "/clusters/$CLUSTER_ID/nodes" -X POST -d "{\"name\":\"$name\",\"addresses\":$addrs}" | jq_py "d['agent_token']")"
    else
      token="$(api "/nodes/$id/token" -X POST | jq_py "d['agent_token']")"
    fi
    rsh "$host" "mkdir -p /root/fleet-install"
    rcp "$host" /root/fleet-install/ "$BIN/fleet-agent" "$ROOT/deploy/node/install-node.sh" "$ROOT/deploy/node/fleet-agent.service"
    rsh "$host" "cd /root/fleet-install && FLEET_SERVER_URL='https://$API_DOMAIN' FLEET_AGENT_TOKEN='$token' ./install-node.sh ./fleet-agent" | tail -5
  done
}

# deploy_probe регистрирует пробу один раз и ставит её как systemd-сервис
deploy_probe() {
  log "проба на $PROBE_HOST"
  load_token
  rcp "$PROBE_HOST" /tmp/ "$BIN/fleet-probe"
  if ! rsh "$PROBE_HOST" "test -f /etc/fleet-probe.env"; then
    local creds
    creds="$(api /probes -X POST -d "{\"name\":\"probe-$PROBE_HOST\",\"region\":\"ru\"}")"
    local key token
    key="$(echo "$creds" | jq_py "d['private_key']")"
    token="$(echo "$creds" | jq_py "d['token']")"
    rsh "$PROBE_HOST" "umask 077; printf 'FLEET_SERVER_URL=https://%s\nFLEET_PROBE_TOKEN=%s\nFLEET_PROBE_PRIVATE_KEY=%s\n' '$API_DOMAIN' '$token' '$key' >/etc/fleet-probe.env"
  fi
  # на одном хосте с control plane проба ходит в fleetd напрямую, без NAT и внешнего DNS
  local url="https://$API_DOMAIN"
  [[ "$PROBE_HOST" == "$CONTROL_HOST" ]] && url="http://127.0.0.1:18080"
  rsh "$PROBE_HOST" "sed -i 's#^FLEET_SERVER_URL=.*#FLEET_SERVER_URL=$url#' /etc/fleet-probe.env"
  rsh "$PROBE_HOST" "bash -s" <<'REMOTE'
set -euo pipefail
install -m 0755 /tmp/fleet-probe /usr/local/bin/fleet-probe
rm -f /tmp/fleet-probe
cat >/etc/systemd/system/fleet-probe.service <<'EOF'
[Unit]
Description=amnezia-fleet probe
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=/etc/fleet-probe.env
ExecStart=/usr/local/bin/fleet-probe
Restart=always
RestartSec=10
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable fleet-probe >/dev/null 2>&1
systemctl restart fleet-probe
sleep 3
systemctl is-active fleet-probe
REMOTE
}

step="${1:-all}"
case "$step" in
  control) build && deploy_control ;;
  cert) deploy_cert ;;
  cluster) deploy_cluster ;;
  nodes) build && deploy_nodes ;;
  probe) build && deploy_probe ;;
  all) build && deploy_control && deploy_cert && deploy_nodes && deploy_probe ;;
  *)
    echo "шаг: all, control, cert, cluster, nodes или probe" >&2
    exit 1
    ;;
esac
