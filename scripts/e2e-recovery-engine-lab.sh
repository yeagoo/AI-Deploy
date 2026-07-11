#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

APPLY="${OPSCTL_ENGINE_LAB_APPLY:-0}"
REGISTRY_DIR="${OPSCTL_ENGINE_LAB_REGISTRY:-$ROOT_DIR/examples/registry}"
STATE_DIR="${OPSCTL_ENGINE_LAB_STATE:-}"
FIXTURE_ROOT="${OPSCTL_ENGINE_LAB_FIXTURES:-}"
PROFILE_ID="${OPSCTL_ENGINE_LAB_PROFILE_ID:-}"
OPSCTL_BIN="${OPSCTL_BIN:-$ROOT_DIR/target/debug/opsctl}"

if [ "$APPLY" != "1" ]; then
  cat <<EOF
Recovery engine lab is disabled by default.

Set OPSCTL_ENGINE_LAB_APPLY=1 and provide:
  OPSCTL_ENGINE_LAB_REGISTRY   registry with version-pinned recovery profiles
  OPSCTL_ENGINE_LAB_FIXTURES   absolute fixture root

Each profile requires <fixture-root>/<profile-id>/baseline. An optional
dirty-shutdown directory enables the dirty-shutdown case. Images must already
exist locally because the recovery executor uses --pull never.
EOF
  exit 0
fi

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "SKIP: Docker daemon is unavailable for the recovery engine lab" >&2
  exit 77
fi
if [ -z "$FIXTURE_ROOT" ] || [[ "$FIXTURE_ROOT" != /* ]]; then
  echo "OPSCTL_ENGINE_LAB_FIXTURES must be an absolute directory" >&2
  exit 1
fi
if [ ! -d "$REGISTRY_DIR" ] || [ ! -d "$FIXTURE_ROOT" ]; then
  echo "registry or fixture directory is missing" >&2
  exit 1
fi
if [ -z "$STATE_DIR" ]; then
  STATE_DIR="$(mktemp -d)"
  trap 'rm -rf -- "$STATE_DIR"' EXIT INT TERM
else
  mkdir -p "$STATE_DIR"
fi
if [ ! -x "$OPSCTL_BIN" ]; then
  cargo build --all-features
fi

args=(
  --registry "$REGISTRY_DIR"
  --state-dir "$STATE_DIR"
  backup volume-protect lab-run
  --fixture-root "$FIXTURE_ROOT"
  --execute
  --json
)
if [ -n "$PROFILE_ID" ]; then
  args+=(--profile-id "$PROFILE_ID")
fi

report="$STATE_DIR/recovery-engine-lab-report.json"
"$OPSCTL_BIN" "${args[@]}" >"$report"
python3 - "$report" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if report.get("status") != "completed" or not report.get("ok"):
    raise SystemExit("recovery engine lab did not complete successfully")
if report.get("cases_passed", 0) < 5:
    raise SystemExit("recovery engine lab did not pass the required qualification cases")
if report.get("cases_failed", 0) != 0:
    raise SystemExit("recovery engine lab reported failed cases")
print(f"PASS: recovery engine lab passed {report['cases_passed']} case(s)")
PY
