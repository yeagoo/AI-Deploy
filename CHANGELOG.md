# Changelog

## 0.6.1 - 2026-07-11

- Added an opt-in, six-hour-capped global-lock wait for reviewed scheduled mutations while preserving fail-fast interactive behavior by default.
- Serialized repository checks with backup, restore-drill, and recovery mutations and bounded lock metadata diagnostics to prevent concurrent history writes and oversized error output.
- Spread daily backup and weekly check/restore timers deterministically across a 23-hour window, with explicit service timeouts, private temporary directories, restrictive umasks, and privilege hardening.
- Generalized the Debian package regression gate to verify the actual candidate/rollback versions and assert the 0.6.1 scheduler payload through upgrade, downgrade, re-upgrade, reinstall, and removal.

## 0.6.0 - 2026-07-11

- Expanded recovery qualification to six bounded cases covering baseline, dirty shutdown, missing image, copy limit, resource floor, and timeout boundary, with cleanup-integrity and legacy journal compatibility checks.
- Added explicit cleanup-request evidence backfill planning and trend recording that classify exact matches, ambiguity, missing/stale proof, profile onboarding, and orphan-volume protection without approving or deleting resources.
- Added signed external retention-attestation import, dual-control checks, restorable signed evidence archives, isolated Restic/rustic archive drills, and evidence-key disaster-recovery readiness reporting without claiming provider immutability.
- Added disabled-by-default evidence verification, signed checkpoint, and recovery-lab systemd timers plus an aggregate recovery SLO/OpenMetrics report.
- Added volume-level recovery timelines and qualification/retention/key-DR/SLO views in TUI, six read-only audited MCP tools, a 0.5 journal fixture, and package/release coverage for the new contracts.
- Hardened execute paths with global serialization and high-risk audit classification; malformed, oversized, or symlinked drill journals now fail closed.

## 0.5.0 - 2026-07-10

- Added a versioned recovery engine lab that reuses the production isolated verifier for baseline, dirty-shutdown, and missing-image cases, journals results, and ships a disabled-by-default Docker E2E runner.
- Added typed application-stack recovery on generated internal-only networks with no host ports, version-pinned local images, bounded resources, fixed localhost health/business probes, and generated-resource cleanup.
- Added bounded recovery-profile metadata detection, review-only planning, create-new draft output, and conflict/environment/local-image validation for PostgreSQL, MySQL/MariaDB, Redis, and MinIO.
- Added expiring/revocable evidence-key trust, systemd credential-directory signing, signed audit checkpoints, aggregate evidence verification, and signed-bundle Restic/rustic export with external WORM retention explicitly required.
- Added state/package compatibility reporting, a TUI Recovery view, and read-only MCP failure-matrix, current gap-rescan, and evidence-audit verification tools.
- Preserved CLI-only mutation, local-image-only recovery, manual approval and deletion, and explicit unavailable results for Docker/package/cloud prerequisites.

## 0.4.0 - 2026-07-10

- Added exact-volume recovery profiles with version-pinned PostgreSQL, MySQL/MariaDB, Redis, and MinIO isolated boot adapters, local-image-only execution, no container network, temporary working copies, and bounded CPU/memory/PID/disk/time limits.
- Added allowlisted file-count, SHA-256, read-only SQL, Redis key-count, and MinIO readiness recovery probes; configured probe or boot failures block cleanup evidence registration.
- Added create-new Ed25519 evidence keys, detached immutable-manifest signatures, strict trusted-key verification, optional signature-required handoff policy, a cross-workflow tamper-evident audit chain, and read-only audit bundle export.
- Added a read-only production failure matrix, current evidence-gap rescan, real local Restic backup/check/restore E2E, and release-gate failure-matrix coverage.
- Preserved CLI-only mutation, read-only MCP, manual approval/deletion, and explicit reporting when Docker, images, keys, package runners, or cloud credentials are unavailable.

## 0.3.0 - 2026-07-10

- Added bounded serial protection campaigns with capacity reserve, duration/failure fuses, lifecycle status, evidence-gap deltas, snapshot-reusing resume, and terminal audited abort.
- Added explicit database verification strength with read-only SQLite integrity/open checks and structural PostgreSQL, MySQL/MariaDB, Redis, and MinIO validation.
- Added SHA-256 sealed manual handoff manifests, expiry/request binding, tamper checks, and current-drift reconciliation that records finalize evidence without deleting resources.
- Added read-only OpenMetrics output, archive-before-rewrite journal maintenance, alert cooldown/recovery state, TUI summaries, and read-only MCP views.
- Added a disabled-by-default systemd campaign resume timer and kept campaign creation, approval, reconciliation writes, and every destructive action outside MCP.

## 0.2.0 - 2026-07-10

- Added exact Docker volume cleanup evidence resolution with content-change invalidation and optional live repository snapshot/tag verification.
- Added controlled orphan-volume Restic/rustic protection with isolated restore, bounded hash and database-feature verification.
- Added versioned run lifecycle journals, metrics, run inspection, snapshot-reusing resume, and bounded staging cleanup.
- Added serial batch planning/execution with item, per-volume byte, and total-byte limits.
- Added opt-in failure delivery through configured operational alert sinks.
- Added item workflow, finalize/handoff, volume-protect history, run status, TUI filtering, and read-only MCP views.
- Kept approval and destructive Docker cleanup outside all automated paths.
