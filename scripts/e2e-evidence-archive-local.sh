#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! command -v restic >/dev/null 2>&1; then
  echo "SKIP: restic is not installed" >&2
  exit 77
fi

work_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT INT TERM

export RESTIC_REPOSITORY="$work_dir/repository"
export RESTIC_PASSWORD="opsctl-evidence-archive-e2e"
export AWS_ACCESS_KEY_ID="local-e2e"
export AWS_SECRET_ACCESS_KEY="local-e2e"

state_dir="$work_dir/state"
manifest="$work_dir/manifest.json"
bundle="$work_dir/evidence-bundle.json"
restore_root="$work_dir/drills"
mkdir -p "$state_dir" "$restore_root"
printf '%s\n' '{"schema_version":"opsctl.e2e_manifest.v1","ok":true}' >"$manifest"
restic init >/dev/null
cargo build --all-features >/dev/null
opsctl_bin="$ROOT_DIR/target/debug/opsctl"
common=(--registry examples/server-registry --state-dir "$state_dir")

"$opsctl_bin" "${common[@]}" registry drift cleanup-request evidence-keygen \
  --key-id archive-e2e --execute --json >/dev/null
"$opsctl_bin" "${common[@]}" registry drift cleanup-request manifest-sign \
  "$manifest" --key-id archive-e2e --execute --json >/dev/null
"$opsctl_bin" "${common[@]}" registry drift cleanup-request audit-bundle \
  "$manifest" --output-file "$bundle" --execute --json >/dev/null
"$opsctl_bin" "${common[@]}" registry drift cleanup-request manifest-sign \
  "$bundle" --key-id archive-e2e --execute --json >/dev/null

archive_report="$work_dir/archive-report.json"
"$opsctl_bin" "${common[@]}" registry drift cleanup-request evidence-worm-export \
  "$bundle" --repository-id restic-r2-main --execute --json >"$archive_report"
snapshot_id="$(python3 - "$archive_report" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
if not report.get("ok"):
    raise SystemExit("evidence archive export failed")
print(report["data"]["snapshot_id"])
PY
)"

drill_report="$work_dir/drill-report.json"
"$opsctl_bin" "${common[@]}" backup volume-protect archive-drill \
  --repository-id restic-r2-main \
  --repository-snapshot "$snapshot_id" \
  --bundle-name "$(basename "$bundle")" \
  --restore-root "$restore_root" \
  --execute --json >"$drill_report"
python3 - "$drill_report" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
data = report.get("data", {})
if not report.get("ok") or data.get("status") != "verified":
    raise SystemExit("evidence archive restore drill failed")
if not data.get("signature_valid") or not data.get("cleanup_complete"):
    raise SystemExit("restored signature or generated-directory cleanup was not verified")
print("PASS: signed evidence archive export/restore/relocated-verify/cleanup")
PY
