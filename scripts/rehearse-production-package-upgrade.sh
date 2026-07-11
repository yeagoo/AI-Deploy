#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT_DIR=""
OUTPUT_ROOT="${OPSCTL_PACKAGE_REHEARSAL_ROOT:-/var/backups/opsctl-upgrade-rehearsals}"
IMAGE="${OPSCTL_DEB_TEST_IMAGE:-debian:13}"
EXECUTE=0

usage() {
  echo "usage: $0 --snapshot DIR [--output-root DIR] [--image IMAGE] [--execute]" >&2
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --snapshot) SNAPSHOT_DIR="${2:?missing --snapshot value}"; shift 2 ;;
    --output-root) OUTPUT_ROOT="${2:?missing --output-root value}"; shift 2 ;;
    --image) IMAGE="${2:?missing --image value}"; shift 2 ;;
    --execute) EXECUTE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "unknown argument: $1" ;;
  esac
done

[ -n "$SNAPSHOT_DIR" ] || { usage; fail "--snapshot is required"; }
for command in docker jq sha256sum dpkg-deb realpath; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
if [ ! -d "$SNAPSHOT_DIR" ] || [ -L "$SNAPSHOT_DIR" ]; then
  fail "snapshot directory is unsafe or missing"
fi
SNAPSHOT_DIR="$(realpath -e "$SNAPSHOT_DIR")"
for file in manifest.json input-0.1.0.deb input-0.6.0.deb; do
  if [ ! -f "$SNAPSHOT_DIR/$file" ] || [ -L "$SNAPSHOT_DIR/$file" ]; then
    fail "snapshot package artifact is unsafe or missing: $file"
  fi
done
jq -e '.schema_version == "opsctl.production_upgrade_snapshot.v1" and .consistent == true' \
  "$SNAPSHOT_DIR/manifest.json" >/dev/null || fail "snapshot manifest is invalid"
old_version="$(dpkg-deb -f "$SNAPSHOT_DIR/input-0.1.0.deb" Version)"
candidate_version="$(dpkg-deb -f "$SNAPSHOT_DIR/input-0.6.0.deb" Version)"
[ "$old_version" = "0.1.0" ] || fail "rollback package must be 0.1.0"
[ "$candidate_version" = "0.6.0" ] || fail "candidate package must be 0.6.0"

cat <<EOF
production package rehearsal plan
  snapshot=$SNAPSHOT_DIR
  image=$IMAGE
  transition=0.1.0 -> 0.6.0 -> 0.1.0 -> 0.6.0
  maintainer_scripts=executed_in_container
  production_data_mounted=false
  output_root=$OUTPUT_ROOT
  execute=$EXECUTE
EOF
[ "$EXECUTE" -eq 1 ] || exit 0
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

expected_old_sha="$(jq -r '.package_inputs.rollback_deb.sha256' "$SNAPSHOT_DIR/manifest.json")"
expected_candidate_sha="$(jq -r '.package_inputs.candidate_deb.sha256' "$SNAPSHOT_DIR/manifest.json")"
old_sha="$(sha256sum "$SNAPSHOT_DIR/input-0.1.0.deb" | awk '{print $1}')"
candidate_sha="$(sha256sum "$SNAPSHOT_DIR/input-0.6.0.deb" | awk '{print $1}')"
[ "$old_sha" = "$expected_old_sha" ] || fail "rollback package checksum does not match snapshot manifest"
[ "$candidate_sha" = "$expected_candidate_sha" ] || fail "candidate package checksum does not match snapshot manifest"

mkdir -p "$OUTPUT_ROOT"
[ ! -L "$OUTPUT_ROOT" ] || fail "output root cannot be a symlink"
OUTPUT_ROOT="$(realpath -e "$OUTPUT_ROOT")"
chmod 0700 "$OUTPUT_ROOT"
umask 077
work_dir="$(mktemp -d "$OUTPUT_ROOT/.package-rehearsal.XXXXXX")"
cleanup() {
  if [ -n "${work_dir:-}" ] && [ -d "$work_dir" ]; then
    rm -rf -- "$work_dir"
  fi
}
trap cleanup EXIT

set +e
OPSCTL_DEB_TEST_APPLY=1 \
OPSCTL_DEB_TEST_IMAGE="$IMAGE" \
OPSCTL_DEB_PATH="$SNAPSHOT_DIR/input-0.6.0.deb" \
OPSCTL_PREVIOUS_DEB="$SNAPSHOT_DIR/input-0.1.0.deb" \
  "$ROOT_DIR/scripts/test-deb-install.sh" > "$work_dir/container.log" 2>&1
test_status=$?
set -e
chmod 0400 "$work_dir/container.log"
created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "$test_status" -ne 0 ]; then
  jq -n \
    --arg created_at "$created_at" \
    --arg snapshot "$SNAPSHOT_DIR" \
    --arg image "$IMAGE" \
    --argjson exit_code "$test_status" \
    '{schema_version:"opsctl.production_package_rehearsal.v1",created_at:$created_at,ok:false,status:"blocked",production_ready:false,read_only_production:true,snapshot:$snapshot,image:$image,container_exit_code:$exit_code,limitations:["disposable Debian package rehearsal failed; inspect the root-only container.log","production package, services, timers, registry, and state were not changed"]}' \
    > "$work_dir/package-report.json"
  chmod 0400 "$work_dir/package-report.json"
  failed_dir="$OUTPUT_ROOT/package-rehearsal-failed-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mv "$work_dir" "$failed_dir"
  work_dir=""
  chmod 0700 "$failed_dir"
  trap - EXIT
  echo "$failed_dir" >&2
  exit "$test_status"
fi
jq -n \
  --arg created_at "$created_at" \
  --arg snapshot "$SNAPSHOT_DIR" \
  --arg image "$IMAGE" \
  --arg old_sha "$old_sha" \
  --arg candidate_sha "$candidate_sha" \
  '{schema_version:"opsctl.production_package_rehearsal.v1",created_at:$created_at,ok:true,status:"passed",production_ready:false,read_only_production:true,snapshot:$snapshot,image:$image,versions:{before:"0.1.0",upgrade:"0.6.0",rollback:"0.1.0",reupgrade:"0.6.0"},checks:{real_dpkg:true,maintainer_scripts_executed:true,systemd_payload_checked:true,registry_sentinel_preserved:true,state_sentinel_preserved:true,rollback_removed_candidate_only_units:true,reupgrade_passed:true,package_remove_preserved_data:true},hashes:{rollback_deb:$old_sha,candidate_deb:$candidate_sha},limitations:["container used package-generated fixture registry/state rather than production data","external backup repositories and service credentials were not exercised","production package, services, timers, registry, and state were not changed"]}' \
  > "$work_dir/package-report.json"
chmod 0400 "$work_dir/package-report.json"
final_dir="$OUTPUT_ROOT/package-rehearsal-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mv "$work_dir" "$final_dir"
work_dir=""
chmod 0700 "$final_dir"
trap - EXIT
echo "$final_dir"
