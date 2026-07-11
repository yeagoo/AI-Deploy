#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

installed_version="$(dpkg-query -W -f='${Version}' opsctl 2>/dev/null || true)"
if [ "$installed_version" != "0.1.0" ]; then
  if [ "${OPSCTL_LEGACY_UPGRADE_REHEARSAL_REQUIRED:-0}" = "1" ]; then
    echo "legacy production upgrade rehearsal requires installed opsctl 0.1.0; observed ${installed_version:-missing}" >&2
    exit 1
  fi
  echo "SKIP: immutable 0.1.0 production-capture rehearsal requires an installed 0.1.0 payload; observed ${installed_version:-missing}" >&2
  echo "Use test-deb-install.sh with OPSCTL_PREVIOUS_DEB for the current patch transition." >&2
  exit 0
fi

work_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

registry="$work_dir/registry"
state="$work_dir/state"
snapshots="$work_dir/snapshots"
rehearsals="$work_dir/rehearsals"
plan_output="$work_dir/plan-only"
cp -a examples/server-registry "$registry"
mkdir -p "$state/deploy-journals" "$state/restore-drills" "$state/volume-protect-restores"
printf 'fixture\n' > "$state/fixture.txt"
ln -s fixture.txt "$state/fixture-link"

scripts/capture-production-upgrade-state.sh \
  --registry "$registry" \
  --state "$state" \
  --output-root "$plan_output" \
  --old-deb target/release-dist/v0.1.0/opsctl_0.1.0_arm64.deb \
  --candidate-deb target/release-dist/v0.6.0/opsctl_0.6.0_arm64.deb >/dev/null
test ! -e "$plan_output"

scripts/capture-production-upgrade-state.sh \
  --registry "$registry" \
  --state "$state" \
  --output-root "$snapshots" \
  --old-deb target/release-dist/v0.1.0/opsctl_0.1.0_arm64.deb \
  --candidate-deb target/release-dist/v0.6.0/opsctl_0.6.0_arm64.deb \
  --execute >/dev/null

snapshot="$(find "$snapshots" -mindepth 1 -maxdepth 1 -type d -name 'snapshot-*' -print -quit)"
test -n "$snapshot"
jq -e '.consistent == true and .versions.installed == "0.1.0" and .versions.candidate == "0.6.0"' "$snapshot/manifest.json" >/dev/null
(
  cd "$snapshot"
  sha256sum -c SHA256SUMS >/dev/null
)

scripts/rehearse-production-upgrade.sh \
  --snapshot "$snapshot" \
  --output-root "$rehearsals" \
  --execute >/dev/null

report="$(find "$rehearsals" -mindepth 2 -maxdepth 2 -type f -name report.json -print -quit)"
test -n "$report"
jq -e '.ok == true and .status == "passed_offline_payload_rehearsal" and .checks.exact_installed_binary_restored == true and .production_ready == false' "$report" >/dev/null
test "$(cat "$state/fixture.txt")" = "fixture"
test -L "$state/fixture-link"

bad_state="$work_dir/bad-state"
mkdir -p "$bad_state"
bad_name=$'bad\tname'
touch "$bad_state/$bad_name"
if scripts/capture-production-upgrade-state.sh \
  --registry "$registry" \
  --state "$bad_state" \
  --output-root "$work_dir/bad-snapshots" \
  --old-deb target/release-dist/v0.1.0/opsctl_0.1.0_arm64.deb \
  --candidate-deb target/release-dist/v0.6.0/opsctl_0.6.0_arm64.deb \
  --execute >/dev/null 2>&1; then
  echo "ambiguous-path capture unexpectedly succeeded" >&2
  exit 1
fi
test ! -e "$work_dir/bad-snapshots" || test -z "$(find "$work_dir/bad-snapshots" -mindepth 1 -print -quit)"

corrupt="$work_dir/corrupt-snapshot"
cp -a "$snapshot" "$corrupt"
chmod u+w "$corrupt/manifest.json"
printf 'tampered\n' >> "$corrupt/manifest.json"
if scripts/rehearse-production-upgrade.sh \
  --snapshot "$corrupt" \
  --output-root "$work_dir/corrupt-rehearsal" \
  --execute >/dev/null 2>&1; then
  echo "corrupt snapshot rehearsal unexpectedly succeeded" >&2
  exit 1
fi

fake_bin="$work_dir/fake-bin"
mkdir -p "$fake_bin"
# The generated test program must expand its own positional argument.
# shellcheck disable=SC2016
printf '#!/usr/bin/env sh\nif [ "${1:-}" = "info" ]; then exit 0; fi\nexit 23\n' > "$fake_bin/docker"
chmod 0755 "$fake_bin/docker"
set +e
PATH="$fake_bin:$PATH" scripts/rehearse-production-package-upgrade.sh \
  --snapshot "$snapshot" \
  --output-root "$work_dir/failed-package-rehearsal" \
  --execute >/dev/null 2>&1
package_status=$?
set -e
test "$package_status" -eq 23
failed_report="$(find "$work_dir/failed-package-rehearsal" -mindepth 2 -maxdepth 2 -type f -name package-report.json -print -quit)"
test -n "$failed_report"
jq -e '.ok == false and .status == "blocked" and .container_exit_code == 23' "$failed_report" >/dev/null
test "$(stat -c '%a' "$(dirname "$failed_report")/container.log")" = "400"
echo "PASS: production snapshot, offline 0.1.0 -> 0.6.0 upgrade, validation, and exact rollback rehearsal"
