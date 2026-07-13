#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_QUALITY="${OPSCTL_GATE_QUALITY:-1}"
RUN_DEB_TEST="${OPSCTL_GATE_DEB_TEST:-0}"
RUN_E2E="${OPSCTL_GATE_E2E:-0}"
RUN_E2E_DEB="${OPSCTL_GATE_E2E_DEB:-1}"
RUN_RELEASE="${OPSCTL_GATE_RELEASE:-0}"
RELEASE_OUT="${OPSCTL_GATE_RELEASE_OUT:-}"
PREVIOUS_DEB="${OPSCTL_GATE_PREVIOUS_DEB:-}"
DEB_USE_SUDO="${OPSCTL_GATE_DEB_USE_SUDO:-0}"

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "$1 is required" >&2
    exit 1
  fi
}

run_quality() {
  require_command cargo
  if ! command -v cargo-audit >/dev/null 2>&1; then
    echo "cargo-audit is required for OPSCTL_GATE_QUALITY=1" >&2
    exit 1
  fi
  if ! command -v cargo-deny >/dev/null 2>&1; then
    echo "cargo-deny is required for OPSCTL_GATE_QUALITY=1" >&2
    exit 1
  fi
  pending_snapshot="$(find tests -type f -name '*.pending-snap' -print -quit)"
  if [ -n "$pending_snapshot" ]; then
    echo "unresolved insta snapshot is not allowed: $pending_snapshot" >&2
    exit 1
  fi

  cargo fmt --check
  scripts/check-release-identity.sh >/dev/null
  cargo clippy --all-targets --all-features -- -D warnings
  cargo test --all-features
  scripts/test-managed-delivery-templates.sh
  scripts/test-failure-matrix.sh
  cargo audit
  cargo deny check
}

run_deb_test() {
  require_command docker
  use_sudo=0
  if ! docker info >/dev/null 2>&1; then
    if [ "$DEB_USE_SUDO" != "1" ]; then
      echo "docker daemon access is required for OPSCTL_GATE_DEB_TEST=1; set OPSCTL_GATE_DEB_USE_SUDO=1 on reviewed root-only Docker hosts" >&2
      exit 1
    fi
    require_command sudo
    if ! sudo docker info >/dev/null 2>&1; then
      echo "Docker daemon is unavailable through the reviewed sudo path" >&2
      exit 1
    fi
    use_sudo=1
  fi
  deb_path="$(scripts/build-deb.sh | tail -n 1)"
  deb_env=("OPSCTL_DEB_PATH=$deb_path" "OPSCTL_DEB_TEST_APPLY=1")
  if [ -n "$PREVIOUS_DEB" ]; then
    deb_env+=("OPSCTL_PREVIOUS_DEB=$PREVIOUS_DEB")
  fi
  if [ "$use_sudo" = "1" ]; then
    sudo env "${deb_env[@]}" "$ROOT_DIR/scripts/test-deb-install.sh"
  else
    env "${deb_env[@]}" scripts/test-deb-install.sh
  fi
}

run_release() {
  require_command python3
  if [ -n "$RELEASE_OUT" ]; then
    release_dir="$(OPSCTL_RELEASE_OUT="$RELEASE_OUT" scripts/release.sh | tail -n 1)"
  else
    release_dir="$(scripts/release.sh | tail -n 1)"
  fi
  scripts/release-verify.sh "$release_dir"
}

if [ "$RUN_QUALITY" = "1" ]; then
  run_quality
else
  echo "skipping quality gate: OPSCTL_GATE_QUALITY=$RUN_QUALITY"
fi

if [ "$RUN_DEB_TEST" = "1" ]; then
  run_deb_test
else
  echo "skipping Debian install regression: OPSCTL_GATE_DEB_TEST=$RUN_DEB_TEST"
fi

if [ "$RUN_E2E" = "1" ]; then
  OPSCTL_E2E_APPLY=1 OPSCTL_E2E_DEB="$RUN_E2E_DEB" scripts/e2e-digitalocean.sh
else
  echo "skipping DigitalOcean E2E: OPSCTL_GATE_E2E=$RUN_E2E"
fi

if [ "$RUN_RELEASE" = "1" ]; then
  run_release
else
  echo "skipping release packaging: OPSCTL_GATE_RELEASE=$RUN_RELEASE"
fi

echo "opsctl release gate completed"
