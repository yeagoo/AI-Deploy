#!/usr/bin/env bash
set -euo pipefail

cargo test --all-features volume_recovery::tests
cargo test --all-features evidence_crypto::tests
cargo test --all-features release_matrix::tests
cargo test --all-features recovery_lab::tests
cargo test --all-features recovery_onboarding::tests
cargo test --all-features evidence_backfill::tests
cargo test --all-features evidence_retention::tests
cargo test --all-features recovery_governance::tests
cargo test --all-features mcp::tests
scripts/test-production-upgrade-rehearsal.sh

if command -v restic >/dev/null 2>&1; then
  scripts/e2e-volume-protect-local.sh
  scripts/e2e-evidence-archive-local.sh
else
  echo "SKIP: real local repository E2E (restic unavailable)" >&2
fi

if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  if [ "${OPSCTL_ENGINE_LAB_APPLY:-0}" = "1" ]; then
    scripts/e2e-recovery-engine-lab.sh
  else
    echo "SKIP: recovery engine lab requires OPSCTL_ENGINE_LAB_APPLY=1 and fixtures" >&2
  fi
else
  echo "SKIP: recovery engine lab (Docker daemon unavailable)" >&2
fi

echo "PASS: bounded failure matrix"
