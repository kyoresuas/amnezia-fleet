#!/usr/bin/env bash
# Раскладывает SSH-ключ на все хосты из inventory.env, пароли нигде не сохраняются
# ./deploy/bootstrap.sh [путь к inventory.env]
set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
INVENTORY="${1:-$DIR/inventory.env}"
KEY="${FLEET_SSH_KEY:-$HOME/.ssh/amnezia_fleet}"

if [[ ! -f "$INVENTORY" ]]; then
  echo "нет $INVENTORY, скопируйте deploy/inventory.env.example и заполните" >&2
  exit 1
fi
# shellcheck source=/dev/null
source "$INVENTORY"
SSH_USER="${SSH_USER:-root}"

if ! command -v sshpass >/dev/null; then
  echo "нужен sshpass: brew install sshpass" >&2
  exit 1
fi
if [[ ! -f "$KEY" ]]; then
  ssh-keygen -q -t ed25519 -N "" -C "amnezia-fleet" -f "$KEY"
  echo "создан ключ $KEY"
fi

# список "роль host" без повторов хостов
targets=""
add() {
  [[ -z "$2" ]] && return 0
  case " $targets " in *"|$2|"*) return 0 ;; esac
  targets="$targets $1|$2|"
}
add control "${CONTROL_HOST:-}"
add probe "${PROBE_HOST:-}"
for node in "${NODES[@]}"; do
  read -r name host _ <<<"$node"
  add "$name" "$host"
done

pub="$(cat "$KEY.pub")"
ok=0
fail=0
for item in $targets; do
  role="${item%%|*}"
  host="${item#*|}"
  host="${host%|}"
  target="$SSH_USER@$host"
  if ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new "$target" true 2>/dev/null; then
    echo "[$role] $target: ключ уже работает"
    ok=$((ok + 1))
    continue
  fi
  read -rsp "[$role] пароль $target: " pass
  echo
  # только пароль, иначе ssh переберёт локальные ключи и упрётся в MaxAuthTries
  if SSHPASS="$pass" sshpass -e ssh -o PubkeyAuthentication=no -o PreferredAuthentications=password,keyboard-interactive \
    -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 "$target" \
    "umask 077; mkdir -p ~/.ssh; grep -qxF '$pub' ~/.ssh/authorized_keys 2>/dev/null || echo '$pub' >> ~/.ssh/authorized_keys" &&
    ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 "$target" true; then
    echo "[$role] $target: ключ установлен"
    ok=$((ok + 1))
  else
    echo "[$role] $target: не получилось, проверьте адрес и пароль" >&2
    fail=$((fail + 1))
  fi
  unset pass
done

echo "готово: $ok, ошибок: $fail"
echo "дальше доступ только по ключу $KEY, пароли можно сменить"
[[ $fail -eq 0 ]]
