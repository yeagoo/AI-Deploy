#!/usr/bin/env bash
set -euo pipefail

APPLY="${OPSCTL_SUDOERS_APPLY:-0}"
AI_USER="${OPSCTL_AI_USER:-ai-deploy}"
DEST="${OPSCTL_SUDOERS_DEST:-/etc/sudoers.d/opsctl-helper}"

case "$AI_USER" in
  ""|*[!A-Za-z0-9_.-]*)
    echo "invalid OPSCTL_AI_USER: $AI_USER" >&2
    exit 1
    ;;
esac

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

cat > "$tmp" <<EOF
# Managed opsctl helper policy.
# Review before installing. This policy must not grant Docker, shell, rm,
# systemctl, or general root access to AI tool users.

Cmnd_Alias OPSCTL_HELPER = /usr/bin/opsctl helper run-deploy-operation *, /usr/local/bin/opsctl helper run-deploy-operation *

$AI_USER ALL=(root) NOPASSWD: OPSCTL_HELPER
EOF
chmod 0440 "$tmp"

if command -v visudo >/dev/null 2>&1; then
  visudo -cf "$tmp"
elif [ "$APPLY" = "1" ]; then
  echo "visudo is required to install sudoers policy" >&2
  exit 1
fi

if [ "$APPLY" != "1" ]; then
  cat "$tmp"
  cat <<EOF

Dry-run only. To install:
  sudo OPSCTL_AI_USER=$AI_USER OPSCTL_SUDOERS_APPLY=1 scripts/install-sudoers.sh
EOF
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "run as root to install sudoers policy" >&2
  exit 1
fi

install -m 0440 "$tmp" "$DEST"
visudo -cf "$DEST"

if command -v opsctl >/dev/null 2>&1; then
  opsctl helper sudoers-check --path "$DEST" >/dev/null
fi

echo "installed sudoers policy: $DEST"
