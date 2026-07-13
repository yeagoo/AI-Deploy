#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: opsctl-git-push-deliver.sh <full-commit> <branch>" >&2
  exit 64
fi

commit="$1"
branch="$2"
case "$commit" in
  (*[!0-9a-f]*|'') echo "full commit must be lowercase hexadecimal" >&2; exit 64 ;;
esac
if [ "${#commit}" -ne 40 ] && [ "${#commit}" -ne 64 ]; then
  echo "full commit must contain 40 or 64 hexadecimal characters" >&2
  exit 64
fi

: "${OPSCTL_DELIVERY_PROJECT_ROOT:?set an absolute checked-out project root}"
: "${OPSCTL_DELIVERY_SERVICE_ID:?set the registered managed service id}"
: "${OPSCTL_DELIVERY_RUNTIME_USER:?set the non-root managed runtime user}"

allowed_branch="${OPSCTL_DELIVERY_BRANCH:-main}"
if [ "$branch" != "$allowed_branch" ]; then
  echo "pushed branch is not authorized for delivery" >&2
  exit 77
fi
case "$OPSCTL_DELIVERY_PROJECT_ROOT" in
  (/*) ;;
  (*) echo "OPSCTL_DELIVERY_PROJECT_ROOT must be absolute" >&2; exit 64 ;;
esac

opsctl_bin="${OPSCTL_BIN:-/usr/bin/opsctl}"
registry="${OPSCTL_REGISTRY:-/srv/server-registry}"
state_dir="${OPSCTL_STATE_DIR:-/var/lib/opsctl}"
delivery_mode="${OPSCTL_DELIVERY_MODE:-execute}"
case "$delivery_mode" in
  (dry-run|execute) ;;
  (*) echo "OPSCTL_DELIVERY_MODE must be dry-run or execute" >&2; exit 64 ;;
esac
for absolute_path in "$opsctl_bin" "$registry" "$state_dir"; do
  case "$absolute_path" in
    (/*) ;;
    (*) echo "opsctl binary, Registry, and State paths must be absolute" >&2; exit 64 ;;
  esac
done
if [ ! -x "$opsctl_bin" ]; then
  echo "opsctl binary is not executable" >&2
  exit 69
fi
args=(
  --registry "$registry"
  --state-dir "$state_dir"
  --actor git-push
  project deliver "$OPSCTL_DELIVERY_PROJECT_ROOT"
  --service-id "$OPSCTL_DELIVERY_SERVICE_ID"
  --runtime-user "$OPSCTL_DELIVERY_RUNTIME_USER"
  --profile "${OPSCTL_DELIVERY_PROFILE:-auto}"
  --environment production
  --tls "${OPSCTL_DELIVERY_TLS:-automatic}"
  --commit "$commit"
  --branch "$branch"
  --"$delivery_mode"
  --json
)

if [ -n "${OPSCTL_DELIVERY_PORT:-}" ]; then
  case "$OPSCTL_DELIVERY_PORT" in
    (*[!0-9]*|'') echo "OPSCTL_DELIVERY_PORT must be numeric" >&2; exit 64 ;;
  esac
  if [ "$OPSCTL_DELIVERY_PORT" -lt 1 ] || [ "$OPSCTL_DELIVERY_PORT" -gt 65535 ]; then
    echo "OPSCTL_DELIVERY_PORT must be between 1 and 65535" >&2
    exit 64
  fi
  args+=(--port "$OPSCTL_DELIVERY_PORT")
fi
if [ -n "${OPSCTL_DELIVERY_DOMAIN:-}" ]; then
  args+=(--domain "$OPSCTL_DELIVERY_DOMAIN")
fi
if [ -n "${OPSCTL_DELIVERY_ENV_FILE:-}" ]; then
  case "$OPSCTL_DELIVERY_ENV_FILE" in
    (/*) ;;
    (*) echo "OPSCTL_DELIVERY_ENV_FILE must be absolute" >&2; exit 64 ;;
  esac
  args+=(--env-file "$OPSCTL_DELIVERY_ENV_FILE")
fi
if [ -n "${OPSCTL_DELIVERY_SYSTEMD_UNIT:-}" ]; then
  args+=(--systemd-unit "$OPSCTL_DELIVERY_SYSTEMD_UNIT")
fi
if [ -n "${OPSCTL_DELIVERY_STATIC_DESTINATION:-}" ]; then
  case "$OPSCTL_DELIVERY_STATIC_DESTINATION" in
    (/*) ;;
    (*) echo "OPSCTL_DELIVERY_STATIC_DESTINATION must be absolute" >&2; exit 64 ;;
  esac
  args+=(--static-destination "$OPSCTL_DELIVERY_STATIC_DESTINATION")
fi

exec "$opsctl_bin" "${args[@]}"
