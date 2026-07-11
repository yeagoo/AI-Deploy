# Quality Strategy

`opsctl` is a single-server CLI / TUI / MCP safety controller. Its quality bar is different from a Web SaaS or a desktop app.

The highest-risk areas are:

- command safety
- registry correctness
- state consistency
- dangerous operation policy
- audit log completeness
- stable JSON/MCP output
- safe Docker/Caddy/systemd inspection
- snapshot and rollback correctness

## Current Quality Commands

Run these on every change:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
scripts/test-failure-matrix.sh
cargo audit
cargo deny check
scripts/test-deb-install.sh
scripts/release.sh
```

Production release candidates must also pass the production upgrade rehearsal against the selected candidate. The immutable 0.1.0 to 0.6.0 rehearsal remains rollback evidence; subsequent patch candidates use the generalized Debian package test with explicit candidate and previous-package paths to prove data preservation and exact version transitions without touching the live package or systemd.

`scripts/test-production-upgrade-rehearsal.sh` executes its legacy production-capture fixture only while the host still has 0.1.0 installed. On upgraded hosts it reports an explicit skip because manufacturing a 0.1.0 installed payload would invalidate the capture contract. Set `OPSCTL_LEGACY_UPGRADE_REHEARSAL_REQUIRED=1` when that exact pre-upgrade state is mandatory; direct patch-package tests set `OPSCTL_PREVIOUS_DEB`, while the aggregate release gate uses the scoped variable below.

When invoking the aggregate release gate, pass the previous patch package as `OPSCTL_GATE_PREVIOUS_DEB`. The gate scopes it only to the disposable Debian transition step so `OPSCTL_PREVIOUS_DEB` cannot alter quality-test or failure-matrix contracts.

On hosts where the reviewed Docker socket is root-only, add `OPSCTL_GATE_DEB_USE_SUDO=1`. This elevates only `scripts/test-deb-install.sh` and its disposable container; Cargo quality checks and release packaging remain unprivileged.

When Docker is available, `scripts/rehearse-production-package-upgrade.sh --snapshot <snapshot> --execute` is the real Debian maintainer-script gate. It validates upgrade, forced downgrade, re-upgrade, reinstall, removal, package-only systemd payload changes, and registry/state sentinel preservation in a disposable container.

The real recovery engine lab is opt-in because it requires reviewed, version-pinned local images and operator-provided fixtures. Run `OPSCTL_ENGINE_LAB_APPLY=1 OPSCTL_ENGINE_LAB_FIXTURES=/absolute/path scripts/e2e-recovery-engine-lab.sh`; missing Docker is reported as skipped, never passed.

The failure-matrix gate always runs the signed evidence-archive Restic E2E when `restic` is installed. It creates an isolated local repository, archives a signed bundle and detached signature, restores the recorded snapshot into a generated directory, verifies the relocated signature, and confirms cleanup. Remote provider Object Lock still requires independently signed operator evidence.

`scripts/test-deb-install.sh` and `scripts/release.sh` are safe to invoke in default mode: the Debian install test does not start Docker unless `OPSCTL_DEB_TEST_APPLY=1`, and release quality gates can be skipped only with `OPSCTL_RELEASE_SKIP_QUALITY=1`.

For 0.6.1 and later, the Debian container test also verifies that the installed scheduled-backup service opts into the bounded lock queue and that its timer uses deterministic delay spreading. Run `systemd-analyze verify packaging/systemd/*.service packaging/systemd/*.timer` before packaging to validate unit syntax and dependencies.

## Current Lint Policy

`Cargo.toml` forbids unsafe code and warns on patterns that are risky for a safety tool:

- `unwrap`
- `expect`
- `panic`
- `todo`
- `unimplemented`
- `dbg!`
- direct stdout/stderr prints outside the CLI boundary

The CLI boundary currently allows printing because `opsctl` is a command-line tool. Core modules should not print directly.

## JSON Contract

All machine-readable command output must use this envelope:

```json
{
  "schema_version": "opsctl.v1",
  "ok": true,
  "data": {}
}
```

Error output must use:

```json
{
  "schema_version": "opsctl.v1",
  "ok": false,
  "error": {
    "message": "..."
  }
}
```

Changing JSON fields is a contract change. Add or update CLI contract tests when changing output.

## Audit Contract

Audit JSONL events must include:

```json
{
  "schema_version": "opsctl.audit.v1",
  "ts": "2026-07-04T10:12:30Z",
  "actor": "codex",
  "command": "doctor",
  "target": "/srv/server-registry",
  "cwd": "/home/ivmm/tools/deploy-tools",
  "result": "success",
  "decision": "allow",
  "reason": null,
  "risk": "medium",
  "dry_run": false
}
```

Audit requirements:

- success paths are logged.
- failure paths are logged when state initialization succeeds.
- each line must be valid JSON.
- audit files are `0600` on Unix.
- state directory is `0700` on Unix.

## SQLite Requirements

SQLite is local state, not the source of truth. YAML registry remains the declared state.

SQLite must be initialized with:

```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
```

Tests should cover:

- initialization is idempotent.
- audit writes succeed.
- failed commands produce audit entries.
- future migrations do not break existing databases.

## Registry Tests

Current Phase 7 validates:

- YAML parses.
- registry files deserialize into strict Rust models.
- service references are checked by `doctor`.
- duplicate IDs and duplicate port bindings are detected.
- public database/cache ports are warned.
- missing production snapshot records are warned.
- project analysis redacts `.env` values.
- scanner detects observed-vs-registered port bind drift.
- read-only external commands are centralized and time-limited.
- deploy plans parse through typed Rust models.
- preflight blocks registered resource conflicts.
- preflight distinguishes `passed`, `needs_approval`, and `blocked`.
- destructive operation findings do not echo raw command text.
- snapshot dry-run does not write artifacts.
- snapshot creation writes a manifest, registry `tar.zst`, server-state JSON, project-analysis JSON, registered database dumps, registered Docker volume archives, and rollback plan.
- rollback without `--dry-run`, `--stage-dir`, or `--restore --approval-token` is rejected.
- rollback dry-run loads only safe snapshot ids, computes a restore diff, and returns an approval token.
- snapshot manifest and rollback plan reads reject symlinks and oversized files.
- registry archive creation rejects path traversal, symlinks, oversized files, and oversized total archives.
- deploy dry-run refuses to run without a verified snapshot when `snapshot_required` is true.
- deploy dry-run recomputes preflight against the current registry.
- deploy dry-run blocks stale embedded `preflight.status` values.
- deploy dry-run emits typed operations instead of shell text.
- Docker Compose preview includes an explicit `--project-name`.
- migration commands are not echoed in deploy reports.
- approval files parse through strict Rust models.
- approval ids are validated before writes.
- requested approvals can be approved or rejected.
- expired approvals cannot be approved.
- expired approved approvals cannot satisfy deploy gates.
- deploy dry-run accepts approved, non-expired scopes for current needs-approval findings.
- approval-type snapshots with `preflight_status: needs_approval` are accepted only when current approvals satisfy the findings.
- TUI dump reads registry, approvals, snapshots, and audit tail without entering interactive mode.

Future registry tests should add fixtures for:

- duplicate domain.
- duplicate Docker volume.
- unknown service type.
- unsafe relative path.
- Caddy route collision.
- backup path collision.
- systemd unit collision.

## CLI Contract Tests

Use:

```text
assert_cmd
insta
tempfile
```

Current integration tests cover:

- `doctor --json` versioned output.
- missing registry JSON error shape.
- failure audit record shape.
- `analyze --json` env redaction and compose risk hints.
- `preflight --json` passed, needs-approval, and blocked statuses.
- `explain-risk --json` returns risk reports without failing the command.
- `snapshot --dry-run --json` does not create artifacts.
- `snapshot --json`, `snapshots --json`, `snapshot-verify --json`, `snapshot-archive-inspect --json`, `snapshot-volume-archive-inspect --json`, and `rollback --dry-run --json` work together.
- `rollback --json` without `--dry-run`, `--stage-dir`, or `--restore --approval-token` fails with a versioned JSON error.
- `deploy --json` without `--dry-run` fails with a versioned JSON error.
- `deploy --dry-run --json` without a required snapshot is blocked.
- `snapshot --json` plus `deploy --dry-run --snapshot <id> --json` returns ready typed operations.
- `tui --dump --json` returns dashboard data.
- `approve --json` updates a requested approval record.
- approved migration plans can become deploy-ready in dry-run without echoing the migration command.

Future contract tests should cover:

- `status --json`
- `services --json`
- `ports --json`
- registry validation commands
- audit query output

## Policy Tests

The policy engine exposes preflight statuses:

```text
passed
needs_approval
blocked
```

Test cases must include:

- `docker compose down -v` -> deny
- `docker volume rm` -> deny
- `docker system prune` -> deny
- `rm -rf` on data path -> deny
- `rm -rf ./build` -> allow or warn
- public database binding -> require approval or deny
- duplicate port -> deny
- duplicate volume -> deny
- Caddy route overwrite -> require approval or deny

## Docker / Compose Tests

Do not start with live Docker tests. Use fixtures for normalized Compose JSON first.

Future fixture classes:

- valid compose
- host port conflict
- `container_name` conflict
- Docker socket mount
- `privileged: true`
- `network_mode: host`
- dangerous bind mount
- volume ownership conflict

## Caddy Tests

Caddy read and write paths must stay separate.

Future tests:

- route normalization from Caddy JSON.
- duplicate host detection.
- wildcard route collision.
- path route collision.
- upstream port conflict.
- Caddy reload plan dry-run.

## Snapshot Tests

Snapshot and restore are high-risk.

Current tests:

- dry-run does not create a snapshot directory.
- snapshot creation writes the core manifest and registry archive.
- snapshot listing finds local manifests.
- rollback dry-run returns a dry-run-only plan.
- unsafe snapshot ids are rejected.

Future tests:

- path traversal denial.
- symlink escaping denial.
- `/proc`, `/sys`, `/dev`, `/run` exclusions.
- max file size enforcement.
- max archive size enforcement.
- restore dry-run before restore.
- conflict check before restore.

## Approval Tests

Current tests:

- approval directory listing.
- requested approval approval.
- requested approval rejection.
- expired approval refusal.
- expired approved approval ignored by deploy gates.
- deploy dry-run readiness with matching approval scope.
- approval command JSON contract.

Future tests:

- multiple approval records covering different scopes.
- rejected approval cannot satisfy deploy.
- expired approved approval cannot satisfy deploy.
- approval constraints surfaced in TUI and MCP.

## TUI Tests

TUI core logic is tested through non-interactive dump mode.

Current tests:

- TUI dump loads the registry.
- TUI dump reports service and port counts.
- CLI `tui --dump --json` uses the versioned output envelope.

Interactive terminal drawing is intentionally thin and should stay separate from safety logic.

## CI Stages

Recommended CI stages:

```text
Stage 1: Rust quality
- cargo fmt --check
- cargo clippy --all-targets --all-features -- -D warnings

Stage 2: Tests
- cargo test --all-features
- cargo nextest run

Stage 3: Security / dependency
- cargo audit
- cargo deny check

Stage 4: Contract tests
- JSON output snapshot tests
- YAML registry fixture tests
- SQLite migration tests

Stage 5: Safety tests
- dangerous command policy tests
- compose conflict tests
- snapshot path safety tests
```

## Phase 7 Baseline

Phase 7 currently has:

- strict Rust models for registry loading.
- doctor consistency checks.
- SQLite state initialization.
- JSONL audit logging.
- versioned JSON output.
- CLI contract tests.
- lint strategy in `Cargo.toml`.
- `opsctl scan` for best-effort read-only observed state.
- `opsctl analyze /path/to/project` for static deployment hints.
- centralized read-only command runner with timeout.
- `.env` key-only scanning with values redacted.
- static Docker Compose risk hints for host ports, `container_name`, host networking, privileged mode, Docker socket mounts, and root bind mounts.
- Dockerfile `EXPOSE` detection.
- Node, PHP/Laravel, Cloudflare/OpenNext, systemd unit, Caddyfile, and deploy-doc indicators.
- `opsctl plan /path/to/project` minimal draft generation.
- `opsctl preflight ./deploy-plan.yml`.
- `opsctl explain-risk ./deploy-plan.yml`.
- built-in policy engine.
- typed deploy plan model.
- policy findings with machine-readable codes.
- non-zero preflight exits for `needs_approval` and `blocked`.
- audit decisions for `allow`, `require_approval`, and `deny`.
- `opsctl snapshot ./deploy-plan.yml`.
- `opsctl snapshot ./deploy-plan.yml --dry-run`.
- `opsctl snapshots`.
- `opsctl snapshot-verify <snapshot-id>`.
- `opsctl snapshot-archive-inspect <snapshot-id>`.
- `opsctl snapshot-volume-archive-inspect <snapshot-id>`.
- `opsctl rollback <snapshot-id> --dry-run`.
- `opsctl rollback <snapshot-id> --stage-dir <dir>`.
- `opsctl rollback <snapshot-id> --restore --approval-token <token>`.
- snapshot manifest and rollback plan serialization.
- registry `tar.zst` snapshots with secure file permissions.
- captured server-state and project-analysis JSON artifacts.
- database dump and Docker volume archive artifact capture.
- rollback diff, approval token, staging, and restore flow tests.
- snapshot artifact indexing through local manifests.
- `opsctl deploy ./deploy-plan.yml --dry-run`.
- required `--snapshot <snapshot-id>` verification for snapshot-required plans.
- fresh preflight evaluation before deploy planning.
- stale embedded preflight detection.
- typed operation previews for preflight, snapshot verification, port reservation, Caddy route writes, Caddy validation/reload, Docker Compose up, migrations, file writes, and registry writes.
- non-dry-run deploy refusal.
- privileged helper design documentation.
- sudoers allowlist example.
- `opsctl approvals`.
- `opsctl approve <approval-id>`.
- `opsctl reject <approval-id> --reason "..."`
- approval expiry enforcement.
- approval-aware deploy dry-run readiness.
- `opsctl tui`.
- `opsctl tui --dump`.
- TUI views for dashboard, services, ports, domains/Caddy routes, Docker projects/volumes, approvals, snapshots/rollback, audit tail, and help.

At Phase 7, the project did not yet have:

- deploy execution without `--dry-run`.
- destructive restore execution.
- database logical dumps.
- Docker volume archives.
- MCP server.
- Caddy Admin API route normalization.
- persistent scan cache in SQLite.
- registry write-back after passed preflight.
- full-screen approval detail/diff view.
- TUI hotkeys that approve/reject directly from the interface.
