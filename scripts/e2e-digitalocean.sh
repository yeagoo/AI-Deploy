#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if [ -f "$HOME/.env" ]; then
  set -a
  # Operator-local optional environment file.
  # shellcheck disable=SC1090,SC1091
  . "$HOME/.env"
  set +a
fi

TOKEN="${DOKEY:-${dokey:-${DIGITALOCEAN_TOKEN:-}}}"
REGION="${DO_REGION:-sfo3}"
SIZE="${DO_SIZE:-s-1vcpu-1gb}"
IMAGE="${DO_IMAGE:-debian-13-x64}"
NAME="${DO_NAME:-opsctl-e2e-$(date +%Y%m%d%H%M%S)}"
SSH_KEYS="${DO_SSH_KEY_IDS:-}"
SSH_PUBLIC_KEY_PATH="${DO_SSH_PUBLIC_KEY_PATH:-}"
APPLY="${OPSCTL_E2E_APPLY:-0}"
DESTROY="${OPSCTL_E2E_DESTROY:-1}"
FULL="${OPSCTL_E2E_FULL:-1}"
USE_DEB="${OPSCTL_E2E_DEB:-1}"
REMOVE_AFTER="${OPSCTL_E2E_REMOVE:-$DESTROY}"
DELETE_CREATED_SSH_KEY="${OPSCTL_E2E_DELETE_CREATED_SSH_KEY:-$DESTROY}"
PREVIOUS_DEB="${OPSCTL_PREVIOUS_DEB:-}"
E2E_DEB_PATH="${OPSCTL_E2E_DEB_PATH:-}"
E2E_BUILD_TOOL="${OPSCTL_E2E_BUILD_TOOL:-cargo}"
E2E_ALLOW_CARGO_CROSS="${OPSCTL_E2E_ALLOW_CARGO_CROSS:-0}"
E2E_REMOTE_BUILD="${OPSCTL_E2E_REMOTE_BUILD:-0}"
E2E_REMOTE_BUILD_JOBS="${OPSCTL_E2E_REMOTE_BUILD_JOBS:-1}"
HELPER_SMOKE="${OPSCTL_E2E_HELPER_SMOKE:-1}"
BACKUP_DRILL="${OPSCTL_E2E_BACKUP_DRILL:-1}"
droplet_id=""
created_ssh_key_id=""
need_remote_deb_build=0
deb_path=""

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

do_api() {
  curl -fsS --retry 6 --retry-all-errors --retry-delay 2 --connect-timeout 15 "$@"
}

dump_remote_diagnostics() {
  if [ -z "${ip:-}" ] || ! declare -F ssh_root >/dev/null 2>&1; then
    return 0
  fi
  echo "E2E remote diagnostics from $ip:" >&2
  ssh_root "set +e
echo '--- /tmp/opsctl-e2e-build-deb.log tail ---'
test -f /tmp/opsctl-e2e-build-deb.log && tail -n 80 /tmp/opsctl-e2e-build-deb.log
echo '--- opsctl tmp json files ---'
for f in /tmp/opsctl-install-check.json /tmp/opsctl-deploy-journals.json /tmp/opsctl-e2e-*.json; do
  if [ -f \"\$f\" ]; then
    echo \"=== \$f ===\"
    sed -n '1,220p' \"\$f\"
  fi
done
echo '--- docker ps -a ---'
command -v docker >/dev/null 2>&1 && docker ps -a
echo '--- compose ps ---'
if command -v docker >/dev/null 2>&1 && [ -f /opt/opsctl-e2e/docker-compose.yml ]; then
  cd /opt/opsctl-e2e && docker compose ps
fi
echo '--- caddy status ---'
systemctl --no-pager --full status caddy 2>/dev/null | sed -n '1,120p'
echo '--- caddy journal tail ---'
journalctl -u caddy -n 80 --no-pager 2>/dev/null
echo '--- caddyfile ---'
test -f /etc/caddy/Caddyfile && sed -n '1,220p' /etc/caddy/Caddyfile
" >&2 || true
}

on_error() {
  local status=$?
  echo "E2E failed with exit code $status" >&2
  dump_remote_diagnostics
  return "$status"
}

trap on_error ERR

image_to_deb_arch() {
  case "$1" in
    *-x64 | *amd64*) echo "amd64" ;;
    *arm64* | *aarch64*) echo "arm64" ;;
    *) dpkg --print-architecture ;;
  esac
}

target_to_deb_arch() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo "amd64" ;;
    aarch64-unknown-linux-gnu) echo "arm64" ;;
    armv7-unknown-linux-gnueabihf) echo "armhf" ;;
    *) echo "unsupported" ;;
  esac
}

deb_arch_to_target() {
  case "$1" in
    amd64) echo "x86_64-unknown-linux-gnu" ;;
    arm64) echo "aarch64-unknown-linux-gnu" ;;
    armhf) echo "armv7-unknown-linux-gnueabihf" ;;
    *) echo "unsupported" ;;
  esac
}

REMOTE_DEB_ARCH="${OPSCTL_E2E_DEB_ARCH:-$(image_to_deb_arch "$IMAGE")}"
REMOTE_TARGET="${OPSCTL_E2E_TARGET:-$(deb_arch_to_target "$REMOTE_DEB_ARCH")}"

if [ "$APPLY" != "1" ]; then
  cat <<EOF
DigitalOcean E2E is disabled by default.

Set OPSCTL_E2E_APPLY=1 to create a temporary droplet.
Required:
  DOKEY or dokey in ~/.env, or DIGITALOCEAN_TOKEN
  DO_SSH_KEY_IDS as comma-separated DigitalOcean SSH key ids or fingerprints

Defaults:
  region=$REGION
  size=$SIZE
  image=$IMAGE
  deb_arch=$REMOTE_DEB_ARCH
  rust_target=$REMOTE_TARGET
  full_deploy_smoke=$FULL
  deb_package_install=$USE_DEB
  deb_package_path=${E2E_DEB_PATH:-auto}
  remote_deb_build=$E2E_REMOTE_BUILD
  helper_sudoers_smoke=$HELPER_SMOKE
  backup_restore_drill=$BACKUP_DRILL
  remove_package_after_test=$REMOVE_AFTER
  ssh_key_ids_configured=$([ -n "$SSH_KEYS" ] && printf yes || printf no)
  ssh_public_key_path=${SSH_PUBLIC_KEY_PATH:-auto}
  destroy_after_test=$DESTROY
EOF
  exit 0
fi

if [ -z "$TOKEN" ]; then
  echo "missing DigitalOcean token: set DOKEY/dokey in ~/.env or DIGITALOCEAN_TOKEN" >&2
  exit 1
fi

require_command curl
require_command jq
require_command ssh
require_command scp

cleanup() {
  if [ "$DESTROY" = "1" ] && [ -n "${droplet_id:-}" ]; then
    do_api -X DELETE "https://api.digitalocean.com/v2/droplets/$droplet_id" \
      -H "Authorization: Bearer $TOKEN" >/dev/null || true
  fi
  if [ "$DELETE_CREATED_SSH_KEY" = "1" ] && [ -n "${created_ssh_key_id:-}" ]; then
    do_api -X DELETE "https://api.digitalocean.com/v2/account/keys/$created_ssh_key_id" \
      -H "Authorization: Bearer $TOKEN" >/dev/null || true
  fi
}
trap cleanup EXIT

if [ "$USE_DEB" = "1" ]; then
  require_command dpkg-deb
  if [ -n "$E2E_DEB_PATH" ]; then
    deb_path="$E2E_DEB_PATH"
  else
    require_command rustc
    host_target="$(rustc -vV | sed -n 's/^host: //p')"
    host_deb_arch="$(target_to_deb_arch "$host_target")"
    if [ "$REMOTE_TARGET" = "unsupported" ]; then
      echo "unsupported DigitalOcean image architecture for .deb E2E: image=$IMAGE arch=$REMOTE_DEB_ARCH" >&2
      exit 1
    fi
    if [ "$host_deb_arch" = "$REMOTE_DEB_ARCH" ]; then
      deb_path="$(OPSCTL_DEB_ARCH="$REMOTE_DEB_ARCH" scripts/build-deb.sh | tail -n 1)"
    else
      if [ "$E2E_BUILD_TOOL" = "cargo" ] && [ "$E2E_ALLOW_CARGO_CROSS" != "1" ]; then
        if [ "$E2E_REMOTE_BUILD" = "1" ]; then
          need_remote_deb_build=1
        else
          cat >&2 <<EOF
host package architecture ($host_deb_arch) does not match droplet architecture ($REMOTE_DEB_ARCH).
Set OPSCTL_E2E_DEB_PATH to an existing $REMOTE_DEB_ARCH package, set OPSCTL_E2E_BUILD_TOOL=cross with a working Docker daemon, or set OPSCTL_E2E_REMOTE_BUILD=1 to build on the temporary droplet.
EOF
          exit 1
        fi
      fi
      if [ "$need_remote_deb_build" != "1" ]; then
        dist_dir="$ROOT_DIR/target/e2e-dist/$NAME"
        OPSCTL_RELEASE_SKIP_QUALITY=1 \
          OPSCTL_RELEASE_BUILD_TOOL="$E2E_BUILD_TOOL" \
          OPSCTL_RELEASE_TARGETS="$REMOTE_TARGET" \
          OPSCTL_RELEASE_OUT="$dist_dir" \
          scripts/release.sh >/tmp/opsctl-e2e-release.log
        deb_path="$(find "$dist_dir" -maxdepth 1 -type f -name "opsctl_*_${REMOTE_DEB_ARCH}.deb" | sort | tail -n 1)"
      fi
    fi
  fi
  if [ "$need_remote_deb_build" != "1" ] && [ ! -f "$deb_path" ]; then
    echo "failed to build or locate Debian package" >&2
    exit 1
  fi
  if [ "$need_remote_deb_build" != "1" ]; then
    deb_arch="$(dpkg-deb -f "$deb_path" Architecture)"
    if [ "$deb_arch" != "$REMOTE_DEB_ARCH" ]; then
      echo "Debian package architecture mismatch: package=$deb_arch droplet=$REMOTE_DEB_ARCH path=$deb_path" >&2
      exit 1
    fi
  fi
  if [ -n "$PREVIOUS_DEB" ] && [ ! -f "$PREVIOUS_DEB" ]; then
    echo "OPSCTL_PREVIOUS_DEB does not exist: $PREVIOUS_DEB" >&2
    exit 1
  fi
  if [ -n "$PREVIOUS_DEB" ]; then
    previous_arch="$(dpkg-deb -f "$PREVIOUS_DEB" Architecture)"
    if [ "$previous_arch" != "$REMOTE_DEB_ARCH" ]; then
      echo "previous Debian package architecture mismatch: package=$previous_arch droplet=$REMOTE_DEB_ARCH path=$PREVIOUS_DEB" >&2
      exit 1
    fi
  fi
else
  cargo build --release
fi

if [ -z "$SSH_KEYS" ]; then
  if [ -z "$SSH_PUBLIC_KEY_PATH" ]; then
    for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
      if [ -f "$candidate" ]; then
        SSH_PUBLIC_KEY_PATH="$candidate"
        break
      fi
    done
  fi
  if [ -z "$SSH_PUBLIC_KEY_PATH" ] || [ ! -f "$SSH_PUBLIC_KEY_PATH" ]; then
    echo "missing DO_SSH_KEY_IDS and no local SSH public key was found; set DO_SSH_KEY_IDS or DO_SSH_PUBLIC_KEY_PATH" >&2
    exit 1
  fi
  public_key="$(cat "$SSH_PUBLIC_KEY_PATH")"
  existing_ssh_key_id="$(do_api "https://api.digitalocean.com/v2/account/keys?per_page=200" \
    -H "Authorization: Bearer $TOKEN" \
    | jq -r --arg public_key "$public_key" '.ssh_keys[]? | select(.public_key == $public_key) | .id' \
    | head -n 1)"
  if [ -n "$existing_ssh_key_id" ]; then
    SSH_KEYS="$existing_ssh_key_id"
  else
    key_payload="$(jq -n \
      --arg name "${DO_SSH_KEY_NAME:-$NAME-key}" \
      --arg public_key "$public_key" \
      '{name:$name, public_key:$public_key}')"
    key_json="$(do_api -X POST "https://api.digitalocean.com/v2/account/keys" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d "$key_payload")"
    created_ssh_key_id="$(printf '%s' "$key_json" | jq -r '.ssh_key.id')"
    if [ -z "$created_ssh_key_id" ] || [ "$created_ssh_key_id" = "null" ]; then
      echo "failed to create temporary DigitalOcean SSH key" >&2
      exit 1
    fi
    SSH_KEYS="$created_ssh_key_id"
  fi
fi

ssh_keys_json="$(printf '%s' "$SSH_KEYS" | jq -R 'split(",") | map(gsub("^\\s+|\\s+$"; ""))')"
create_payload="$(jq -n \
  --arg name "$NAME" \
  --arg region "$REGION" \
  --arg size "$SIZE" \
  --arg image "$IMAGE" \
  --argjson ssh_keys "$ssh_keys_json" \
  '{name:$name, region:$region, size:$size, image:$image, ssh_keys:$ssh_keys, backups:false, ipv6:false, monitoring:false, tags:["opsctl-e2e"]}')"

droplet_json="$(do_api -X POST "https://api.digitalocean.com/v2/droplets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$create_payload")"
droplet_id="$(printf '%s' "$droplet_json" | jq -r '.droplet.id')"

echo "created droplet $droplet_id ($NAME), waiting for IPv4..."
ip=""
for _ in $(seq 1 90); do
  droplet_get="$(do_api "https://api.digitalocean.com/v2/droplets/$droplet_id" \
    -H "Authorization: Bearer $TOKEN")"
  ip="$(printf '%s' "$droplet_get" | jq -r '.droplet.networks.v4[]? | select(.type=="public") | .ip_address' | head -n 1)"
  if [ -n "$ip" ] && [ "$ip" != "null" ]; then
    break
  fi
  sleep 5
done

if [ -z "$ip" ] || [ "$ip" = "null" ]; then
  echo "timed out waiting for droplet public IPv4" >&2
  exit 1
fi

echo "waiting for SSH on $ip..."
for _ in $(seq 1 60); do
  if ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=5 "root@$ip" "true" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

ssh_opts=(-o StrictHostKeyChecking=accept-new)
ssh_root() {
  # Callers pass reviewed remote argv fragments only.
  # shellcheck disable=SC2029
  ssh "${ssh_opts[@]}" "root@$ip" "$@"
}
scp_root() {
  scp "${ssh_opts[@]}" "$@"
}

build_remote_deb() {
  require_command tar
  src_archive="$(mktemp)"
  tar \
    --exclude='./target' \
    --exclude='./.git' \
    --exclude='./imports' \
    --exclude='./tmp' \
    --exclude='./.direnv' \
    -czf "$src_archive" .
  ssh_root "rm -rf /tmp/opsctl-src /tmp/opsctl-src.tar.gz && mkdir -p /tmp/opsctl-src"
  scp_root "$src_archive" "root@$ip:/tmp/opsctl-src.tar.gz"
  rm -f "$src_archive"
  ssh_root "tar -xzf /tmp/opsctl-src.tar.gz -C /tmp/opsctl-src"
  ssh_root "DEBIAN_FRONTEND=noninteractive apt-get update"
  ssh_root "DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl build-essential pkg-config dpkg-dev jq sudo adduser"
  ssh_root "if [ ! -x /root/.cargo/bin/cargo ]; then curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable; fi"
  ssh_root "cd /tmp/opsctl-src && remote_arch=\$(dpkg --print-architecture) && PATH=\"/root/.cargo/bin:\$PATH\" CARGO_BUILD_JOBS='$E2E_REMOTE_BUILD_JOBS' OPSCTL_DEB_ARCH=\"\$remote_arch\" scripts/build-deb.sh >/tmp/opsctl-e2e-build-deb.log"
  ssh_root "remote_deb=\$(tail -n 1 /tmp/opsctl-e2e-build-deb.log) && test -f \"\$remote_deb\" && cp \"\$remote_deb\" /tmp/opsctl.deb && dpkg-deb -f /tmp/opsctl.deb Architecture | grep -qx '$REMOTE_DEB_ARCH'"
}

if [ "$USE_DEB" = "1" ]; then
  if [ "$need_remote_deb_build" = "1" ]; then
    build_remote_deb
  else
    ssh_root "rm -rf /tmp/opsctl-src && mkdir -p /tmp/opsctl-src"
    scp_root "$deb_path" "root@$ip:/tmp/opsctl.deb"
  fi
  if [ -n "$PREVIOUS_DEB" ]; then
    scp_root "$PREVIOUS_DEB" "root@$ip:/tmp/opsctl-previous.deb"
  fi
  ssh_root "DEBIAN_FRONTEND=noninteractive apt-get update"
  ssh_root "DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates adduser sudo"
  if [ -n "$PREVIOUS_DEB" ]; then
    ssh_root "dpkg -i /tmp/opsctl-previous.deb && test -x /usr/bin/opsctl"
  fi
  ssh_root "dpkg -i /tmp/opsctl.deb"
  ssh_root "test -x /usr/bin/opsctl && id opsctl && getent group opsctl"
  ssh_root "test -f /usr/lib/systemd/system/opsctl-install-check.service && test -f /usr/lib/systemd/system/opsctl-install-check.timer"
  ssh_root "test -f /usr/share/opsctl/templates/sudoers.opsctl.example && test -f /usr/share/opsctl/scripts/install-sudoers.sh"
  ssh_root "test \"\$(stat -c '%a' /srv/server-registry)\" = '750' && test \"\$(stat -c '%G' /srv/server-registry)\" = 'opsctl'"
  ssh_root "test \"\$(stat -c '%a' /var/lib/opsctl)\" = '700' && test \"\$(stat -c '%U:%G' /var/lib/opsctl)\" = 'opsctl:opsctl'"
  ssh_root "test \"\$(stat -c '%U:%G' /var/lib/opsctl/opsctl.db)\" = 'opsctl:opsctl' && test \"\$(stat -c '%U:%G' /var/lib/opsctl/audit.log)\" = 'opsctl:opsctl'"
  ssh_root "cp /usr/share/opsctl/templates/sudoers.opsctl.example /tmp/opsctl-sudoers && chmod 0440 /tmp/opsctl-sudoers"
  ssh_root "/usr/bin/opsctl helper sudoers-check --path /tmp/opsctl-sudoers --json >/tmp/opsctl-sudoers-check.json && visudo -cf /tmp/opsctl-sudoers"
  ssh_root "dpkg -i /tmp/opsctl.deb"
  opsctl_bin="/usr/bin/opsctl"
else
  ssh_root "rm -rf /tmp/opsctl-src && mkdir -p /tmp/opsctl-src/target/release /tmp/opsctl-src/scripts"
  scp_root target/release/opsctl "root@$ip:/tmp/opsctl-src/target/release/opsctl"
  scp_root scripts/install-debian.sh "root@$ip:/tmp/opsctl-src/scripts/install-debian.sh"
  scp_root -r examples "root@$ip:/tmp/opsctl-src/"
  ssh_root "cd /tmp/opsctl-src && sh scripts/install-debian.sh target/release/opsctl"
  opsctl_bin="/usr/local/bin/opsctl"
fi

ssh_root "runuser -u opsctl -- $opsctl_bin --registry /srv/server-registry --state-dir /var/lib/opsctl install-check --json >/tmp/opsctl-install-check.json"
ssh_root "$opsctl_bin --registry /srv/server-registry --state-dir /var/lib/opsctl deploy-journals --json >/tmp/opsctl-deploy-journals.json"
ssh_root "test -s /tmp/opsctl-install-check.json && test -s /tmp/opsctl-deploy-journals.json"

if [ "$USE_DEB" = "1" ] && [ "$HELPER_SMOKE" = "1" ]; then
  echo "running sudoers/helper smoke..."
  ssh_root "id opsctl-ai-e2e >/dev/null 2>&1 || useradd --create-home --shell /bin/bash opsctl-ai-e2e"
  ssh_root "OPSCTL_AI_USER=opsctl-ai-e2e OPSCTL_SUDOERS_APPLY=1 /usr/share/opsctl/scripts/install-sudoers.sh >/tmp/opsctl-install-sudoers.log"
  ssh_root "/usr/bin/opsctl helper sudoers-check --path /etc/sudoers.d/opsctl-helper --json >/tmp/opsctl-e2e-sudoers-installed.json"
  ssh_root "mkdir -p /opt/opsctl-e2e"
  ssh_root "cat > /opt/opsctl-e2e/helper-plan.yml" <<'REMOTE_HELPER_PLAN'
id: deploy_opsctl_e2e_helper
actor: opsctl-e2e
project_root: /opt/opsctl-e2e
intent: deploy
environment: staging
changes:
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
REMOTE_HELPER_PLAN
  opsctl_helper_remote="/usr/bin/opsctl --actor opsctl-e2e"
  helper_dry_run_json="$(ssh_root "$opsctl_helper_remote deploy /opt/opsctl-e2e/helper-plan.yml --dry-run --json")"
  helper_token="$(printf '%s' "$helper_dry_run_json" | jq -r '.data.execution_approval_token')"
  if [ -z "$helper_token" ] || [ "$helper_token" = "null" ]; then
    echo "helper deploy dry-run did not return an execution token" >&2
    exit 1
  fi
  helper_approval_json="$(ssh_root "$opsctl_helper_remote request-deploy-execution /opt/opsctl-e2e/helper-plan.yml --reason opsctl-e2e-helper --json")"
  helper_approval_id="$(printf '%s' "$helper_approval_json" | jq -r '.data.approval.id')"
  ssh_root "$opsctl_helper_remote approve '$helper_approval_id' --json >/tmp/opsctl-e2e-helper-approve.json"
  ssh_root "su -s /bin/sh opsctl-ai-e2e -c 'sudo -n /usr/bin/opsctl helper run-deploy-operation /opt/opsctl-e2e/helper-plan.yml --operation 1 --approval-token \"$helper_token\" --json >/tmp/opsctl-e2e-helper-run.json'"
  ssh_root "test -s /tmp/opsctl-e2e-helper-run.json"
fi

if [ "$FULL" = "1" ]; then
  echo "running full Docker/Caddy deploy smoke..."
  ssh_root "DEBIAN_FRONTEND=noninteractive apt-get update"
  ssh_root "DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl jq caddy"
  ssh_root "if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then curl -fsSL https://get.docker.com | sh; fi"
  ssh_root "systemctl enable --now docker"
  ssh_root "systemctl enable --now caddy"
  ssh_root "mkdir -p /opt/opsctl-e2e"
  ssh_root "cat > /opt/opsctl-e2e/docker-compose.yml" <<'REMOTE_COMPOSE'
services:
  web:
    image: nginx:alpine
    ports:
      - "127.0.0.1:18080:80"
    restart: unless-stopped
REMOTE_COMPOSE
  ssh_root "cat > /opt/opsctl-e2e/deploy-plan.yml" <<'REMOTE_PLAN'
id: deploy_opsctl_e2e
actor: opsctl-e2e
project_root: /opt/opsctl-e2e
intent: deploy
environment: staging
changes:
  docker:
    compose_project: opsctl-e2e
    containers:
      - opsctl-e2e-web-1
  ports:
    reserve:
      - 18080
  caddy:
    routes:
      - host: e2e.opsctl.local
        upstream: 127.0.0.1:18080
  health:
    enabled: true
  destructive_ops: []
snapshot_required: false
preflight:
  status: pending
REMOTE_PLAN

  opsctl_remote="$opsctl_bin --registry /srv/server-registry --state-dir /var/lib/opsctl --actor opsctl-e2e"
  dry_run_json="$(ssh_root "$opsctl_remote deploy /opt/opsctl-e2e/deploy-plan.yml --dry-run --json")"
  execution_token="$(printf '%s' "$dry_run_json" | jq -r '.data.execution_approval_token')"
  if [ -z "$execution_token" ] || [ "$execution_token" = "null" ]; then
    echo "deploy dry-run did not return an execution token" >&2
    exit 1
  fi
  approval_json="$(ssh_root "$opsctl_remote request-deploy-execution /opt/opsctl-e2e/deploy-plan.yml --reason opsctl-e2e --json")"
  approval_id="$(printf '%s' "$approval_json" | jq -r '.data.approval.id')"
  ssh_root "$opsctl_remote approve '$approval_id' --json >/tmp/opsctl-e2e-approve.json"
  ssh_root "$opsctl_remote deploy /opt/opsctl-e2e/deploy-plan.yml --execute --approval-token '$execution_token' --json >/tmp/opsctl-e2e-deploy.json"
  ssh_root "$opsctl_remote caddy-routes --json >/tmp/opsctl-e2e-caddy-routes.json"
  ssh_root "$opsctl_remote deploy-journals --json >/tmp/opsctl-e2e-journals-after.json"
  ssh_root "curl -fsS http://127.0.0.1:18080/ | grep -qi nginx"
  ssh_root "jq -e '.data.execution.results[] | select(.kind == \"PostDeployHealthCheck\") | .health_checks[] | select(.kind == \"caddy_http\" and .status == \"success\")' /tmp/opsctl-e2e-deploy.json >/dev/null"

  if [ "$BACKUP_DRILL" = "1" ]; then
    echo "running real restic restore drill smoke..."
    ssh_root "DEBIAN_FRONTEND=noninteractive apt-get install -y restic"
    ssh_root "rm -rf /tmp/opsctl-e2e-backup-registry /tmp/opsctl-e2e-restore /opt/opsctl-e2e-backup /opt/opsctl-e2e-restic-repo && mkdir -p /tmp/opsctl-e2e-backup-registry /opt/opsctl-e2e-backup/dumps"
    ssh_root "printf 'CREATE TABLE app(id int);\\nINSERT INTO app VALUES (1);\\n' >/opt/opsctl-e2e-backup/dumps/app.sql && printf 'payload\\n' >/opt/opsctl-e2e-backup/index.txt"
    ssh_root "RESTIC_PASSWORD=opsctl-e2e-secret restic -r /opt/opsctl-e2e-restic-repo init >/tmp/opsctl-e2e-restic-init.log"
    ssh_root "RESTIC_PASSWORD=opsctl-e2e-secret restic -r /opt/opsctl-e2e-restic-repo backup /opt/opsctl-e2e-backup --tag opsctl --tag service:e2e-backup --tag target:e2e-backup-restic >/tmp/opsctl-e2e-restic-backup.log"
    snapshot_id="$(ssh_root "RESTIC_PASSWORD=opsctl-e2e-secret restic -r /opt/opsctl-e2e-restic-repo snapshots --latest 1 --json | jq -r '.[0].short_id // .[0].id'")"
    if [ -z "$snapshot_id" ] || [ "$snapshot_id" = "null" ]; then
      echo "restic did not return a snapshot id for restore drill" >&2
      exit 1
    fi
    completed_at="$(ssh_root "date -u +%Y-%m-%dT%H:%M:%SZ")"
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/services.yml" <<'REMOTE_SERVICES'
version: 1
services:
  - id: e2e-backup
    name: E2E Backup Service
    root: /opt/opsctl-e2e-backup
    kind: static
    environment: production
    status: active
    data_paths:
      - /opt/opsctl-e2e-backup
    backup_policy: before_deploy
REMOTE_SERVICES
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/ports.yml" <<'REMOTE_PORTS'
version: 1
ports: []
REMOTE_PORTS
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/domains.yml" <<'REMOTE_DOMAINS'
version: 1
domains: []
REMOTE_DOMAINS
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/volumes.yml" <<'REMOTE_VOLUMES'
version: 1
volumes: []
REMOTE_VOLUMES
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/snapshots.yml" <<REMOTE_SNAPSHOTS
version: 1
snapshots:
  - id: e2e-backup-snapshot
    created_at: "$completed_at"
    service_ids:
      - e2e-backup
    scope:
      - database_dump
      - filesystem_manifest
      - registry
    status: complete
REMOTE_SNAPSHOTS
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/backups.yml" <<REMOTE_BACKUPS
version: 1
repositories:
  - id: restic-e2e
    provider: restic
    repository: /opt/opsctl-e2e-restic-repo
    password_env: OPSCTL_E2E_RESTIC_PASSWORD
    status: active
    check_after_backup: true
targets:
  - id: e2e-backup-restic
    service_id: e2e-backup
    repository_id: restic-e2e
    max_age_hours: 168
    include_paths:
      - /opt/opsctl-e2e-backup
    exclude_paths: []
    tags:
      - production
      - before-deploy
    database_dumps:
      - id: e2e-postgres-dump
        kind: postgres
        database: restorecheck
        output_path: /opt/opsctl-e2e-backup/dumps/app.sql
    schedule: before_deploy
    status: active
history:
  - id: backup-e2e-$snapshot_id
    service_id: e2e-backup
    target_id: e2e-backup-restic
    repository_id: restic-e2e
    tool: restic
    completed_at: "$completed_at"
    status: success
    repository_snapshot_id: "$snapshot_id"
REMOTE_BACKUPS
    ssh_root "cp /srv/server-registry/policies.yml /tmp/opsctl-e2e-backup-registry/policies.yml"
    backup_remote="$opsctl_bin --registry /tmp/opsctl-e2e-backup-registry --state-dir /var/lib/opsctl --actor opsctl-e2e"
    ssh_root "OPSCTL_E2E_RESTIC_PASSWORD=opsctl-e2e-secret $backup_remote backup check restic-e2e --json >/tmp/opsctl-e2e-backup-check.json"
    restore_plan_json="$(ssh_root "OPSCTL_E2E_RESTIC_PASSWORD=opsctl-e2e-secret $backup_remote backup restore-plan e2e-backup --repository-snapshot '$snapshot_id' --restore-dir /tmp/opsctl-e2e-restore --json")"
    restore_token="$(printf '%s' "$restore_plan_json" | jq -r '.data.expected_approval_token')"
    if [ -z "$restore_token" ] || [ "$restore_token" = "null" ]; then
      echo "backup restore-plan did not return an approval token" >&2
      exit 1
    fi
    ssh_root "OPSCTL_E2E_RESTIC_PASSWORD=opsctl-e2e-secret OPSCTL_RESTORE_DB_IMPORT_CHECK=1 $backup_remote backup restore e2e-backup --repository-snapshot '$snapshot_id' --restore-dir /tmp/opsctl-e2e-restore --execute --approval-token '$restore_token' --json >/tmp/opsctl-e2e-restore.json"
    ssh_root "$backup_remote backup history --json >/tmp/opsctl-e2e-backup-history.json"
    ssh_root "jq -e '.data.status == \"ready\" and .data.repository_check_targets_blocked == 0 and .data.restore_drill_targets_blocked == 0' /tmp/opsctl-e2e-backup-history.json >/dev/null"
    ssh_root "cat > /tmp/opsctl-e2e-backup-registry/deploy-plan.yml" <<'REMOTE_BACKUP_PLAN'
id: deploy_e2e_backup_gate
actor: opsctl-e2e
service_id: e2e-backup
project_root: /opt/opsctl-e2e-backup
intent: update
environment: production
changes:
  destructive_ops: []
snapshot_required: true
preflight:
  status: pending
REMOTE_BACKUP_PLAN
    ssh_root "OPSCTL_E2E_RESTIC_PASSWORD=opsctl-e2e-secret $backup_remote preflight /tmp/opsctl-e2e-backup-registry/deploy-plan.yml --json >/tmp/opsctl-e2e-backup-preflight.json"
    ssh_root "jq -e '.data.status == \"passed\"' /tmp/opsctl-e2e-backup-preflight.json >/dev/null"
  fi
fi

if [ "$USE_DEB" = "1" ] && [ "$REMOVE_AFTER" = "1" ]; then
  ssh_root "dpkg -r opsctl && test ! -e /usr/bin/opsctl && test -d /srv/server-registry && test -d /var/lib/opsctl"
fi

echo "E2E smoke passed on $ip"
if [ "$DESTROY" != "1" ]; then
  echo "droplet retained: $droplet_id root@$ip"
fi
