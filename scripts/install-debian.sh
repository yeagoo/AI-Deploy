#!/usr/bin/env sh
set -eu

BIN_SRC="${1:-./target/release/opsctl}"
BIN_DST="${OPSCTL_BIN_DST:-/usr/local/bin/opsctl}"
REGISTRY_DIR="${OPSCTL_REGISTRY:-/srv/server-registry}"
STATE_DIR="${OPSCTL_STATE_DIR:-/var/lib/opsctl}"
OPSCTL_USER="${OPSCTL_USER:-opsctl}"
OPSCTL_GROUP="${OPSCTL_GROUP:-opsctl}"

if [ "$(id -u)" -ne 0 ]; then
  echo "run this installer as root, for example: sudo scripts/install-debian.sh ./target/release/opsctl" >&2
  exit 1
fi

if [ ! -f "$BIN_SRC" ]; then
  echo "opsctl binary not found: $BIN_SRC" >&2
  echo "build one first with: cargo build --release" >&2
  exit 1
fi

install -d -m 0755 "$(dirname "$BIN_DST")"
install -m 0755 "$BIN_SRC" "$BIN_DST"
if [ -f "./templates/opsctl.profile.sh" ]; then
  install -m 0644 "./templates/opsctl.profile.sh" /etc/profile.d/opsctl.sh
fi

if command -v getent >/dev/null 2>&1 && ! getent group "$OPSCTL_GROUP" >/dev/null; then
  if command -v addgroup >/dev/null 2>&1; then
    addgroup --system "$OPSCTL_GROUP"
  elif command -v groupadd >/dev/null 2>&1; then
    groupadd --system "$OPSCTL_GROUP"
  fi
fi

if command -v getent >/dev/null 2>&1 && ! getent passwd "$OPSCTL_USER" >/dev/null; then
  if command -v adduser >/dev/null 2>&1; then
    adduser --system --ingroup "$OPSCTL_GROUP" --home "$STATE_DIR" --no-create-home --disabled-login --disabled-password "$OPSCTL_USER"
  elif command -v useradd >/dev/null 2>&1; then
    useradd --system --gid "$OPSCTL_GROUP" --home-dir "$STATE_DIR" --no-create-home --shell /usr/sbin/nologin "$OPSCTL_USER"
  fi
fi

install -d -m 0750 "$REGISTRY_DIR"
install -d -m 0700 "$STATE_DIR"

if [ ! -f "$REGISTRY_DIR/services.yml" ] && [ -d "./examples/server-registry" ]; then
  for file in services.yml ports.yml domains.yml volumes.yml snapshots.yml backups.yml policies.yml AGENTS.md README.md; do
    if [ -f "./examples/server-registry/$file" ]; then
      install -m 0640 "./examples/server-registry/$file" "$REGISTRY_DIR/$file"
    fi
  done
  install -d -m 0700 "$REGISTRY_DIR/approvals"
  install -d -m 0750 "$REGISTRY_DIR/plans" "$REGISTRY_DIR/history"
fi

chmod 2750 "$REGISTRY_DIR"
chmod 0700 "$STATE_DIR"
install -d -m 0700 "$STATE_DIR/deploy-journals"

if command -v getent >/dev/null 2>&1 && getent group "$OPSCTL_GROUP" >/dev/null; then
  chgrp -R "$OPSCTL_GROUP" "$REGISTRY_DIR" || true
  for dir in approvals plans history reviews; do
    if [ -d "$REGISTRY_DIR/$dir" ]; then
      chgrp "$OPSCTL_GROUP" "$REGISTRY_DIR/$dir" || true
      chmod 2750 "$REGISTRY_DIR/$dir" || true
    fi
  done
  find "$REGISTRY_DIR" -type d -exec chmod 2750 {} \; || true
  find "$REGISTRY_DIR" -type f -name '*.yml' -exec chmod 0640 {} \; || true
  find "$REGISTRY_DIR" -type f -name '*.md' -exec chmod 0640 {} \; || true
fi
if command -v getent >/dev/null 2>&1 && getent passwd "$OPSCTL_USER" >/dev/null && getent group "$OPSCTL_GROUP" >/dev/null; then
  chown "$OPSCTL_USER:$OPSCTL_GROUP" "$STATE_DIR" "$STATE_DIR/deploy-journals" || true
fi

"$BIN_DST" --registry "$REGISTRY_DIR" --state-dir "$STATE_DIR" install-check >/dev/null

echo "installed $BIN_DST"
echo "registry: $REGISTRY_DIR"
echo "state:    $STATE_DIR"
