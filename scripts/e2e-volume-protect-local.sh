#!/usr/bin/env bash
set -euo pipefail

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
export RESTIC_PASSWORD="opsctl-local-e2e-only"

mkdir -p "$work_dir/source/nested" "$work_dir/restore"
printf '%s\n' 'opsctl recovery fixture' >"$work_dir/source/nested/data.txt"
dd if=/dev/zero of="$work_dir/source/blob.bin" bs=1024 count=64 status=none

restic init >/dev/null
restic backup --tag opsctl-volume-protect-e2e "$work_dir/source" >/dev/null
snapshot_id="$(restic snapshots --tag opsctl-volume-protect-e2e --json | sed -n 's/.*"short_id":"\([a-f0-9]*\)".*/\1/p' | tail -1)"
if [[ -z "$snapshot_id" ]]; then
  echo "FAIL: restic did not return a snapshot id" >&2
  exit 1
fi

restic check >/dev/null
restic restore "$snapshot_id" --target "$work_dir/restore" >/dev/null
restored_file="$work_dir/restore${work_dir}/source/nested/data.txt"
if [[ ! -f "$restored_file" ]]; then
  echo "FAIL: restored fixture file is missing" >&2
  exit 1
fi
cmp "$work_dir/source/nested/data.txt" "$restored_file"

echo "PASS: real local Restic backup/check/restore verified snapshot $snapshot_id"
