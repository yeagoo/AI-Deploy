#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SNAPSHOT_DIR=""
OUTPUT_ROOT="${OPSCTL_UPGRADE_REHEARSAL_ROOT:-$ROOT_DIR/target/production-upgrade-rehearsals}"
EXECUTE=0
KEEP_ROOTFS=0

usage() {
  echo "usage: $0 --snapshot DIR [--output-root DIR] [--keep-rootfs] [--execute]" >&2
}

fail() {
  echo "error: $*" >&2
  exit 1
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --snapshot) SNAPSHOT_DIR="${2:?missing --snapshot value}"; shift 2 ;;
    --output-root) OUTPUT_ROOT="${2:?missing --output-root value}"; shift 2 ;;
    --keep-rootfs) KEEP_ROOTFS=1; shift ;;
    --execute) EXECUTE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "unknown argument: $1" ;;
  esac
done

[ -n "$SNAPSHOT_DIR" ] || { usage; fail "--snapshot is required"; }
for command in tar zstd sha256sum jq realpath find sort dpkg-deb; do
  command -v "$command" >/dev/null 2>&1 || fail "$command is required"
done
if [ ! -d "$SNAPSHOT_DIR" ] || [ -L "$SNAPSHOT_DIR" ]; then
  fail "snapshot directory is unsafe or missing"
fi
SNAPSHOT_DIR="$(realpath -e "$SNAPSHOT_DIR")"
for file in manifest.json SHA256SUMS registry.tar.zst state.tar.zst installed-package.tar.zst input-0.1.0.deb input-0.6.0.deb; do
  if [ ! -f "$SNAPSHOT_DIR/$file" ] || [ -L "$SNAPSHOT_DIR/$file" ]; then
    fail "snapshot artifact is unsafe or missing: $file"
  fi
done
jq -e '.schema_version == "opsctl.production_upgrade_snapshot.v1" and .consistent == true and .status == "captured"' \
  "$SNAPSHOT_DIR/manifest.json" >/dev/null || fail "snapshot manifest is invalid"
old_version="$(dpkg-deb -f "$SNAPSHOT_DIR/input-0.1.0.deb" Version)"
candidate_version="$(dpkg-deb -f "$SNAPSHOT_DIR/input-0.6.0.deb" Version)"
[ "$old_version" = "0.1.0" ] || fail "rollback package is not version 0.1.0"
[ "$candidate_version" = "0.6.0" ] || fail "candidate package is not version 0.6.0"

cat <<EOF
production upgrade rehearsal plan
  snapshot=$SNAPSHOT_DIR
  rollback_version=$old_version
  candidate_version=$candidate_version
  isolation=disposable_rootfs
  maintainer_scripts=not_executed
  output_root=$OUTPUT_ROOT
  execute=$EXECUTE
EOF
[ "$EXECUTE" -eq 1 ] || exit 0

(
  cd "$SNAPSHOT_DIR"
  sha256sum -c SHA256SUMS >/dev/null
)
zstd -q -t "$SNAPSHOT_DIR/registry.tar.zst"
zstd -q -t "$SNAPSHOT_DIR/state.tar.zst"
zstd -q -t "$SNAPSHOT_DIR/installed-package.tar.zst"

mkdir -p "$OUTPUT_ROOT"
[ ! -L "$OUTPUT_ROOT" ] || fail "output root cannot be a symlink"
OUTPUT_ROOT="$(realpath -e "$OUTPUT_ROOT")"
case "$OUTPUT_ROOT/" in "$SNAPSHOT_DIR/"*) fail "output root cannot be inside the snapshot" ;; esac

umask 077
run_dir="$(mktemp -d "$OUTPUT_ROOT/.rehearsal.XXXXXX")"
rootfs="$run_dir/rootfs"
mkdir -p "$rootfs/srv/server-registry" "$rootfs/var/lib/opsctl"
cleanup() {
  if [ "${KEEP_ROOTFS:-0}" -eq 0 ] && [ -n "${rootfs:-}" ] && [ -d "$rootfs" ]; then
    rm -rf -- "$rootfs"
  fi
}
trap cleanup EXIT

reject_unsafe_members() {
  local archive="$1"
  if zstd -q -dc "$archive" | tar -tf - | awk '$0 ~ /^\// || $0 ~ /(^|\/)\.\.($|\/)/ {found=1} END {exit !found}'; then
    fail "archive contains an unsafe member path: $(basename "$archive")"
  fi
}

reject_package_links() {
  local package="$1"
  if dpkg-deb --fsys-tarfile "$package" | tar -tvf - | awk 'substr($1,1,1) == "l" {found=1} END {exit !found}'; then
    fail "package payload contains a symbolic link and requires separate review: $(basename "$package")"
  fi
}

reject_archive_links() {
  local archive="$1"
  if zstd -q -dc "$archive" | tar -tvf - | awk 'substr($1,1,1) == "l" {found=1} END {exit !found}'; then
    fail "installed package archive contains a symbolic link and requires separate review"
  fi
}

tree_fingerprint() {
  local source="$1"
  find "$source" -xdev -printf '%y\t%P\t%s\t%T@\t%l\n' \
    | LC_ALL=C sort \
    | sha256sum \
    | awk '{print $1}'
}

stable_state_fingerprint() {
  local source="$1"
  find "$source" -xdev -mindepth 1 \
    ! -path "$source/audit.log" \
    ! -path "$source/opsctl.db" \
    ! -path "$source/opsctl.db-shm" \
    ! -path "$source/opsctl.db-wal" \
    ! -path "$source/opsctl.lock" \
    -printf '%y\t%P\t%s\t%T@\t%l\n' \
    | LC_ALL=C sort \
    | sha256sum \
    | awk '{print $1}'
}

for archive in registry.tar.zst state.tar.zst installed-package.tar.zst; do
  reject_unsafe_members "$SNAPSHOT_DIR/$archive"
done
reject_package_links "$SNAPSHOT_DIR/input-0.1.0.deb"
reject_package_links "$SNAPSHOT_DIR/input-0.6.0.deb"
reject_archive_links "$SNAPSHOT_DIR/installed-package.tar.zst"

dpkg-deb -x "$SNAPSHOT_DIR/input-0.1.0.deb" "$rootfs"
zstd -q -dc "$SNAPSHOT_DIR/registry.tar.zst" | tar --no-same-owner -xf - -C "$rootfs/srv/server-registry"
zstd -q -dc "$SNAPSHOT_DIR/state.tar.zst" | tar --no-same-owner -xf - -C "$rootfs/var/lib/opsctl"
zstd -q -dc "$SNAPSHOT_DIR/installed-package.tar.zst" | tar --no-same-owner -xf - -C "$rootfs"

old_binary="$rootfs/usr/bin/opsctl"
[ -x "$old_binary" ] || fail "captured installed binary is missing"
old_observed="$($old_binary --version)"
case "$old_observed" in "opsctl 0.1.0") ;; *) fail "captured installed binary is not 0.1.0" ;; esac
expected_installed_sha="$(jq -r '.installed_binary_sha256' "$SNAPSHOT_DIR/manifest.json")"
old_binary_sha="$(sha256sum "$old_binary" | awk '{print $1}')"
[ "$old_binary_sha" = "$expected_installed_sha" ] || fail "captured installed binary hash does not match manifest"

registry_before="$(tree_fingerprint "$rootfs/srv/server-registry")"
state_before="$(stable_state_fingerprint "$rootfs/var/lib/opsctl")"
dpkg-deb -x "$SNAPSHOT_DIR/input-0.6.0.deb" "$rootfs"
registry_after_upgrade="$(tree_fingerprint "$rootfs/srv/server-registry")"
state_after_upgrade="$(stable_state_fingerprint "$rootfs/var/lib/opsctl")"
[ "$registry_before" = "$registry_after_upgrade" ] || fail "candidate package payload changed registry data"
[ "$state_before" = "$state_after_upgrade" ] || fail "candidate package payload changed stable state data"

candidate_binary="$rootfs/usr/bin/opsctl"
candidate_observed="$($candidate_binary --version)"
case "$candidate_observed" in "opsctl 0.6.0") ;; *) fail "candidate binary is not 0.6.0" ;; esac
candidate_binary_sha="$(sha256sum "$candidate_binary" | awk '{print $1}')"
"$candidate_binary" --registry "$rootfs/srv/server-registry" --state-dir "$rootfs/var/lib/opsctl" registry validate --json > "$run_dir/registry-validate.json"
jq -e '.data.errors == 0' "$run_dir/registry-validate.json" >/dev/null
"$candidate_binary" --registry "$rootfs/srv/server-registry" --state-dir "$rootfs/var/lib/opsctl" install-check --json > "$run_dir/install-check.json"
jq -e '.data.ok == true' "$run_dir/install-check.json" >/dev/null

registry_after_checks="$(tree_fingerprint "$rootfs/srv/server-registry")"
state_after_checks="$(stable_state_fingerprint "$rootfs/var/lib/opsctl")"
[ "$registry_before" = "$registry_after_checks" ] || fail "candidate validation changed registry data"
[ "$state_before" = "$state_after_checks" ] || fail "candidate validation changed stable state data"

dpkg-deb -x "$SNAPSHOT_DIR/input-0.1.0.deb" "$rootfs"
zstd -q -dc "$SNAPSHOT_DIR/installed-package.tar.zst" | tar --no-same-owner -xf - -C "$rootfs"
rollback_observed="$($old_binary --version)"
rollback_sha="$(sha256sum "$old_binary" | awk '{print $1}')"
[ "$rollback_observed" = "opsctl 0.1.0" ] || fail "rollback did not restore version 0.1.0"
[ "$rollback_sha" = "$expected_installed_sha" ] || fail "rollback did not restore the exact installed binary"
[ "$registry_before" = "$(tree_fingerprint "$rootfs/srv/server-registry")" ] || fail "rollback changed registry data"
[ "$state_before" = "$(stable_state_fingerprint "$rootfs/var/lib/opsctl")" ] || fail "rollback changed stable state data"

created_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg created_at "$created_at" \
  --arg snapshot "$SNAPSHOT_DIR" \
  --arg old_binary_sha256 "$old_binary_sha" \
  --arg candidate_binary_sha256 "$candidate_binary_sha" \
  --arg rollback_binary_sha256 "$rollback_sha" \
  --arg registry_fingerprint "$registry_before" \
  --arg state_fingerprint "$state_before" \
  '{schema_version:"opsctl.production_upgrade_rehearsal.v1",created_at:$created_at,ok:true,status:"passed_offline_payload_rehearsal",production_ready:false,read_only_production:true,snapshot:$snapshot,versions:{before:"0.1.0",candidate:"0.6.0",rollback:"0.1.0"},checks:{snapshot_checksums:true,archives_valid:true,unsafe_member_paths:false,candidate_registry_validate:true,candidate_install_check:true,registry_preserved:true,stable_state_preserved:true,exact_installed_binary_restored:true},hashes:{before_binary:$old_binary_sha256,candidate_binary:$candidate_binary_sha256,rollback_binary:$rollback_binary_sha256,registry:$registry_fingerprint,stable_state:$state_fingerprint},maintainer_scripts_executed:false,limitations:["Debian maintainer scripts and systemd daemon-reload require a separate disposable VM/container rehearsal","service environment files and external repositories were not exercised","production package, services, timers, registry, and state were not changed"]}' \
  > "$run_dir/report.json"
chmod 0400 "$run_dir/report.json" "$run_dir/registry-validate.json" "$run_dir/install-check.json"
if [ "$KEEP_ROOTFS" -eq 0 ]; then
  rm -rf -- "$rootfs"
  rootfs=""
fi
final_dir="$OUTPUT_ROOT/rehearsal-$(date -u +%Y%m%dT%H%M%SZ)-$$"
mv "$run_dir" "$final_dir"
chmod 0700 "$final_dir"
trap - EXIT
echo "$final_dir"
