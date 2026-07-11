#!/usr/bin/env bash
set -euo pipefail

OPSCTL_BIN="${OPSCTL_BIN:-opsctl}"
REGISTRY_DIR="${OPSCTL_REGISTRY:-/srv/server-registry}"
STATE_DIR="${OPSCTL_STATE_DIR:-/var/lib/opsctl}"
IMPORT_DIR="${1:-${OPSCTL_IMPORT_DIR:-}}"
ENV_FILE="${OPSCTL_BACKUP_ENV_FILE:-${OPSCTL_RESTIC_ENV_FILE:-}}"
APPLY="${OPSCTL_ONBOARDING_APPLY:-0}"
REPO_INIT="${OPSCTL_ONBOARDING_REPO_INIT:-0}"
SERVICES="${OPSCTL_ONBOARDING_SERVICES:-}"
REPOSITORIES="${OPSCTL_ONBOARDING_REPOSITORIES:-}"
RESTORE_ROOT="${OPSCTL_ONBOARDING_RESTORE_ROOT:-$STATE_DIR/restore-drills}"

opsctl_base=("$OPSCTL_BIN" --registry "$REGISTRY_DIR" --state-dir "$STATE_DIR")

if [ -z "$ENV_FILE" ] && [ -f /etc/opsctl/restic.env ]; then
  ENV_FILE=/etc/opsctl/restic.env
fi

if [ -n "$ENV_FILE" ]; then
  if [ ! -f "$ENV_FILE" ]; then
    echo "backup env file not found: $ENV_FILE" >&2
    exit 2
  fi
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

if [ -n "${OPSCTL_EXTRA_PATHS:-}" ]; then
  PATH="$OPSCTL_EXTRA_PATHS:$PATH"
  export PATH
fi

if [[ "$OPSCTL_BIN" == */* ]]; then
  if [ ! -x "$OPSCTL_BIN" ]; then
    echo "opsctl binary is not executable: $OPSCTL_BIN" >&2
    exit 127
  fi
elif ! command -v "$OPSCTL_BIN" >/dev/null 2>&1; then
  echo "opsctl binary not found in PATH; set OPSCTL_BIN=/path/to/opsctl" >&2
  exit 127
fi

onboarding_check() {
  local args=(backup onboarding-check)
  if [ -n "$IMPORT_DIR" ]; then
    args+=(--import-dir "$IMPORT_DIR")
  fi
  "${opsctl_base[@]}" "${args[@]}"
}

validate_id() {
  local kind="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "invalid $kind id: $value" >&2
    exit 2
  fi
}

if [ "$APPLY" != "1" ]; then
  set +e
  onboarding_check
  status=$?
  set -e
  cat <<'TXT' >&2

Dry-run only. To execute the backup onboarding flow after reviewing the planned commands:

  OPSCTL_ONBOARDING_APPLY=1 \
  OPSCTL_ONBOARDING_REPO_INIT=1 \
  OPSCTL_BACKUP_ENV_FILE=/etc/opsctl/restic.env \
  OPSCTL_ONBOARDING_SERVICES="service-a service-b" \
  OPSCTL_ONBOARDING_REPOSITORIES="repo-a" \
  /usr/share/opsctl/scripts/production-onboarding-check.sh /path/to/generated-import

The apply mode still runs registry promote-import as --dry-run only. Set
OPSCTL_ONBOARDING_REPO_INIT=1 only for a new repository; restic init will fail
against an already initialized repository.
TXT
  exit "$status"
fi

if [ -z "$SERVICES" ]; then
  echo "OPSCTL_ONBOARDING_SERVICES is required when OPSCTL_ONBOARDING_APPLY=1" >&2
  exit 2
fi

if [ -z "$REPOSITORIES" ]; then
  echo "OPSCTL_ONBOARDING_REPOSITORIES is required when OPSCTL_ONBOARDING_APPLY=1" >&2
  exit 2
fi

for repository in $REPOSITORIES; do
  validate_id repository "$repository"
  if [ "$REPO_INIT" = "1" ]; then
    "${opsctl_base[@]}" backup repo-init "$repository"
    "${opsctl_base[@]}" backup repo-init "$repository" \
      --execute \
      --approval-token "repo-init:$repository"
  fi
done

for service in $SERVICES; do
  validate_id service "$service"
  "${opsctl_base[@]}" backup run "$service" --execute
done

for repository in $REPOSITORIES; do
  validate_id repository "$repository"
  "${opsctl_base[@]}" backup check "$repository"
done

drill_args=(backup drill-suite --restore-root "$RESTORE_ROOT" --execute)
for service in $SERVICES; do
  drill_args+=(--service "$service")
done
OPSCTL_RESTORE_DB_IMPORT_CHECK="${OPSCTL_RESTORE_DB_IMPORT_CHECK:-1}" \
  "${opsctl_base[@]}" "${drill_args[@]}"

if [ -n "$IMPORT_DIR" ]; then
  "${opsctl_base[@]}" registry import-check "$IMPORT_DIR" --scan-observed
  "${opsctl_base[@]}" registry promote-import "$IMPORT_DIR" --dry-run --scan-observed
fi

onboarding_check
