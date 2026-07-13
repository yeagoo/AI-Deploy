# opsctl

`opsctl` is a lightweight deployment safety gate for a single Debian server.

It is designed for servers where AI coding tools such as Codex, Claude Code, and opencode help deploy projects directly over SSH. The goal is not to build another control panel. The goal is to make every deployment visible, checked, auditable, and reversible.

## What It Is

`opsctl` keeps a local registry of server facts:

- deployed services
- reserved and observed ports
- domains and Caddy routes
- Docker Compose projects
- container names
- Docker volumes
- data paths
- backup and snapshot records
- pending approvals

Before a new project is deployed, AI tools should create a deploy plan and run:

```bash
opsctl preflight ./deploy-plan.yml
```

If the plan is safe, it can proceed. If it touches production data, routes, ports, volumes, or destructive operations, `opsctl` blocks or asks for human approval.

## What It Is Not

`opsctl` is not:

- a public web control panel
- a PaaS
- a replacement for Docker, Caddy, or systemd
- a generic Docker MCP server
- a shell where AI can run arbitrary root commands
- a secret store

The first version is intentionally local:

```text
CLI for scripts and humans
TUI for SSH-based review
stdio MCP for AI tools
YAML registry for human-readable source of truth
SQLite cache/history for fast lookup
```

## Current Status

Current development has completed through Phase 121, followed by the managed-delivery convergence work in Phases 10–13. The `0.6.3` candidate adds bounded project compilation, domain/TLS and Secret contracts, typed database migrations, health control, supply-chain checks, constrained automatic delivery, and the trusted Git-push bridge; it supersedes the CI-failed 0.6.2 tag without rewriting that published identity. The installed production version remains a separate operational fact and must be verified before use. Automatic approval, arbitrary-project execution, destructive Docker volume cleanup, and broad application/data rollback remain intentionally unsupported.

### Production Database Types

The production registry is mixed database infrastructure, not a single MySQL-family or PostgreSQL-only estate. Backup, restore, and restore-drill logic must follow the registered `database_dumps[].kind` or `database_dumps[].verify_kind` value for each target.

Current production facts include:

- MySQL/MariaDB targets: `rankfan-new`, `docfan-legacy`.
- PostgreSQL targets: `mf8`, `Open-Launch`, `toolso-ai-open`, `pcafev2`, `jiankong`, `pkgseek`, `service`, `supalite`, `xemvip`.
- Source-only or no local database dump targets: `screenhello`, `mariadb-edu-rich`, Caddy/config-only targets.

Do not infer the database engine from a project directory name. For example, `seo-website/mariadb` is a project path/name in the registry; it is not enough evidence to treat every server database as MariaDB.

`opsctl backup doctor` now compares the declared dump engine with read-only hints from registered env files, root `.env*` files, Compose service images/container names, and registered containers. It warns on MySQL/MariaDB versus PostgreSQL family mismatches without printing secret values.

Implemented:

- Rust binary crate.
- `opsctl status`
- `opsctl services`
- `opsctl ports`
- `opsctl registry validate`
- `opsctl registry normalize [--execute]`
- `opsctl registry schemas`
- `opsctl registry export-schema <name>`
- `opsctl registry import-projects --output <dir> [--force] [--scan-observed] <project>...`
- `opsctl registry import-check <dir> [--scan-observed]`
- `opsctl registry promote-import <dir> --dry-run [--scan-observed]`
- `opsctl registry promote-import <dir> --approval-token <token> [--scan-observed]`
- `opsctl backup doctor`
- `opsctl backup readiness`
- `opsctl backup history`
- `opsctl backup volume-protect plan <request-file> --target <volume> --repository-id <repository> [--restore-root <dir>] [--min-verification-strength feature|integrity|boot]`
- `opsctl backup volume-protect run <request-file> --target <volume> --repository-id <repository> [--restore-root <dir>] [--min-verification-strength feature|integrity|boot] [--execute] [--alert-on-failure]`
- `opsctl backup volume-protect history [--limit <n>]`
- `opsctl backup volume-protect status [--run-id <id>] [--limit <n>]`
- `opsctl backup volume-protect resume <run-id> [--execute] [--alert-on-failure]`
- `opsctl backup volume-protect cleanup [--restore-root <dir>] [--keep-days <days>] [--keep-count <count>] [--execute]`
- `opsctl backup volume-protect batch-plan <request-file> --repository-id <repository> [--restore-root <dir>] [--max-items <n>] [--max-total-bytes <bytes>] [--max-volume-bytes <bytes>]`
- `opsctl backup volume-protect batch-run <request-file> --repository-id <repository> [--restore-root <dir>] [--max-items <n>] [--max-total-bytes <bytes>] [--max-volume-bytes <bytes>] [--execute] [--alert-on-failure]`
- `opsctl backup volume-protect campaign-plan <request-file> --repository-id <repository> [--min-free-bytes <bytes>] [--max-failures <n>] [--max-duration-seconds <seconds>]`
- `opsctl backup volume-protect campaign-run <request-file> --repository-id <repository> [campaign limits] [--execute] [--alert-on-failure]`
- `opsctl backup volume-protect campaign-status [--campaign-id <id>] [--limit <n>]`
- `opsctl backup volume-protect campaign-resume <campaign-id> [--execute]`
- `opsctl backup volume-protect campaign-abort <campaign-id> [--reason <reason>] [--execute]`
- `opsctl backup volume-protect metrics [--request-file <cleanup-request>]`
- `opsctl backup volume-protect failure-matrix`
- `opsctl backup volume-protect gap-rescan <cleanup-request>`
- `opsctl backup volume-protect lab-plan [--fixture-root <dir>] [--profile-id <id>]`
- `opsctl backup volume-protect lab-run [--fixture-root <dir>] [--profile-id <id>] [--execute]`
- `opsctl backup volume-protect lab-status [--limit <n>]`
- `opsctl backup volume-protect profile-detect --source-dir <dir> --volume <name>`
- `opsctl backup volume-protect profile-plan --source-dir <dir> --volume <name>`
- `opsctl backup volume-protect profile-draft --source-dir <dir> --volume <name> --output-file <file> [--execute]`
- `opsctl backup volume-protect profile-validate <profile-file>`
- `opsctl backup volume-protect journal-maintain [--archive-dir <dir>] [--keep-lines <n>] [--execute]`
- `opsctl backup plan <service-id> --dry-run`
- `opsctl backup run <service-id> [--target <target-id>] [--execute]`
- `opsctl backup restore-plan <service-id> --repository-snapshot <id> --restore-dir <dir>`
- `opsctl backup restore <service-id> --repository-snapshot <id> --restore-dir <dir> --execute --approval-token <token>`
- `opsctl backup repo-init <repository-id> [--execute --approval-token <token>]`
- `opsctl backup drill-suite [--service <service-id>]... --restore-root <dir> [--execute]`
- `opsctl backup check <repository-id>`
- `opsctl backup prune <repository-id> [--service-id <service-id>] --approval-token <token>`
- `opsctl backup drill-cleanup [--keep-days <days>] [--keep-count <count>] [--execute]`
- `opsctl backup timer plan [--service-id <service-id>] [--repository-id <repository-id>]`
- `opsctl backup timer install [--service-id <service-id>] [--repository-id <repository-id>] [--execute]`
- `opsctl backup timer status [--service-id <service-id>] [--repository-id <repository-id>]`
- `opsctl backup timer monitor [--service-id <service-id>] [--repository-id <repository-id>] [--journal]`
- `opsctl backup timer alert [--service-id <service-id>] [--repository-id <repository-id>] [--journal] [--execute]`
- `opsctl backup timer alert-test [--sink-id <sink-id>] [--execute]`
- `opsctl backup timer alert-status [--sink-id <sink-id>]`
- `opsctl backup timer alert-enable-plan [--id <sink-id>] [--provider <webhook|ntfy|telegram|email>] [--target-env <ENV_NAME>]`
- `opsctl backup timer alert-env-template [--id <sink-id>] [--provider <webhook|ntfy|telegram|email>] [--target-env <ENV_NAME>] [--env-file <path>]`
- `opsctl backup timer alert-configure <sink-id> --provider <webhook|ntfy|telegram|email> --target-env <ENV_NAME> [--owner <owner>] [--status active|disabled] [--execute]`
- `opsctl backup onboarding-check [--import-dir <dir>]`
- `opsctl backup s3-smoke --endpoint <endpoint> --region <region> --provider <provider> --bucket <bucket> [--prefix <prefix>] [--execute]`
- `opsctl deploy-gates`
- `opsctl doctor`
- `opsctl scan`
- `opsctl caddy-routes [--adapt] [--admin]`
- `opsctl registry drift list`
- `opsctl registry drift groups`
- `opsctl registry drift suggest`
- `opsctl registry drift governance`
- `opsctl registry drift review export`
- `opsctl registry drift review apply <review-file> [--execute]`
- `opsctl registry drift cleanup-plan`
- `opsctl registry drift cleanup-request export`
- `opsctl registry drift cleanup-request verify <request-file>`
- `opsctl registry drift cleanup-request triage <request-file>`
- `opsctl registry drift cleanup-request dashboard <request-file>`
- `opsctl registry drift cleanup-request worklist <request-file> [--kind <kind>] [--status all|unknown|needs_cleanup] [--limit <n>]`
- `opsctl registry drift cleanup-request evidence <request-file> [--request-id <id>|--target <target>|--all] [--execute]`
- `opsctl registry drift cleanup-request evidence-resolve <request-file> [--request-id <id>|--target <target>|--all] [--max-age-hours <hours>] [--verify-repository] [--execute]`
- `opsctl registry drift cleanup-request evidence-keygen --key-id <rotation-id> [--execute]`
- `opsctl registry drift cleanup-request evidence-key-trust --key-id <rotation-id> --expires-at <RFC3339> [--execute]`
- `opsctl registry drift cleanup-request evidence-key-revoke --key-id <rotation-id> --reason <text> [--execute]`
- `opsctl registry drift cleanup-request evidence-key-status [--key-id <rotation-id>]`
- `opsctl registry drift cleanup-request manifest-sign <manifest> --key-id <rotation-id> [--credential-name <name>] [--execute]`
- `opsctl registry drift cleanup-request manifest-verify <manifest>`
- `opsctl registry drift cleanup-request audit-verify`
- `opsctl registry drift cleanup-request audit-checkpoint --key-id <rotation-id> [--credential-name <name>] [--execute]`
- `opsctl registry drift cleanup-request evidence-verify-all`
- `opsctl registry drift cleanup-request audit-bundle <manifest> --output-file <absolute-new-file> [--execute]`
- `opsctl registry drift cleanup-request evidence-worm-export <bundle> --repository-id <id> [--execute]`
- `opsctl registry drift cleanup-request execution-plan <request-file>`
- `opsctl registry drift cleanup-request execution-gate <request-file>`
- `opsctl registry drift cleanup-request approval-pack <request-file> [--kind <kind>] [--status all|unknown|needs_cleanup|approved|rejected] [--limit <n>]`
- `opsctl registry drift cleanup-request volume-ownership <request-file> [--status all|unknown|needs_cleanup|approved|rejected] [--limit <n>]`
- `opsctl registry drift cleanup-request handoff-pack <request-file> --expires-at <RFC3339> [--ticket <id>] [--execute]`
- `opsctl registry drift cleanup-request manifest-status <manifest-file>`
- `opsctl registry drift cleanup-request reconcile <manifest-file> [--reason <reason>] [--execute]`
- `opsctl registry drift explain [--code <code>] [--target <target>]`
- `opsctl registry drift service-add <service-id> [--root <path>] [--kind <kind>] [--deploy-method <method>] [--reason <reason>] [--execute]`
- `opsctl registry drift ignore [--kind <kind>] [--code <code>] [--target <target>|--target-prefix <prefix>|--target-suffix <suffix>|--target-contains <text>] --reason <reason> --expires-at <RFC3339> [--execute]`
- `opsctl registry drift adopt [--kind <kind>] --target <target> --service-id <service-id> [--reason <reason>] [--operator-note <note>] [--review-status <status>] [--execute]`
- `opsctl analyze /path/to/project`
- `opsctl project profiles`
- `opsctl project compile /path/to/project [--profile auto] [--service-id <id>] [--runtime-user <user>] [--port <port>]`
- `opsctl project git-trigger /path/to/project --commit <full-id> --branch <branch> [--execute]`
- `opsctl project authorize-delivery /path/to/project --commit <full-id> --branch <branch> --reason "..."`
- `opsctl project deliver /path/to/project --commit <full-id> --branch <branch> (--dry-run|--execute)`
- `opsctl plan /path/to/project`
- `opsctl preflight ./deploy-plan.yml`
- `opsctl explain-risk ./deploy-plan.yml`
- `opsctl snapshot ./deploy-plan.yml`
- `opsctl snapshot ./deploy-plan.yml --dry-run`
- `opsctl snapshots`
- `opsctl snapshot-inspect <snapshot-id>`
- `opsctl snapshot-verify <snapshot-id>`
- `opsctl snapshot-archive-inspect <snapshot-id>`
- `opsctl snapshot-volume-archive-inspect <snapshot-id>`
- `opsctl snapshot-coverage`
- `opsctl rollback <snapshot-id> --dry-run`
- `opsctl rollback <snapshot-id> --stage-dir <new-dir>`
- `opsctl rollback <snapshot-id> --restore --approval-token <token> [--restore-config] [--restore-data]`
- `opsctl deploy ./deploy-plan.yml --dry-run --snapshot <snapshot-id>`
- `opsctl request-deploy-execution ./deploy-plan.yml --snapshot <snapshot-id> --reason "..."`
- `opsctl deploy ./deploy-plan.yml --execute --snapshot <snapshot-id> --approval-token <token>`
- `opsctl deploy-journals`
- `opsctl deploy-journal-inspect <journal-id>`
- `opsctl deploy-resume ./deploy-plan.yml --journal <journal-id> --dry-run`
- `opsctl request-deploy-resume ./deploy-plan.yml --journal <journal-id> --reason "..."`
- `opsctl deploy-resume ./deploy-plan.yml --journal <journal-id> --execute --approval-token <token>`
- `opsctl deploy-health-controller ./deploy-plan.yml --journal <journal-id> --dry-run`
- `opsctl request-health-rollback ./deploy-plan.yml --journal <journal-id> --reason "..."`
- `opsctl deploy-health-controller ./deploy-plan.yml --journal <journal-id> --execute --approval-token <token>`
- `opsctl install-check`
- `opsctl helper run-deploy-operation ./deploy-plan.yml --operation <n> --snapshot <snapshot-id> --approval-token <token>`
- `opsctl helper sudoers-check --path /etc/sudoers.d/opsctl-helper`
- `opsctl approvals`
- `opsctl audit --limit 20`
- `opsctl approve <approval-id>`
- `opsctl reject <approval-id> --reason "..."`
- `opsctl tui`
- `opsctl tui --dump`
- `opsctl mcp`
- versioned `--json` output for implemented commands.
- YAML registry loading.
- strict embedded JSON Schema validation for registry YAML files.
- backup repository and target registry loading.
- backup history registry loading.
- optional backup history freshness policy through `max_age_hours`.
- registered backup repository check history and restore drill history loading.
- production `before_deploy` backup history gates that require recent successful backup history, repository check history, and restore drill history.
- Restic/rustic backup dry-run planning and controlled CLI execution with required environment variable names only.
- controlled repository init, repository check, and approval-gated prune commands.
- controlled Restic/rustic execution maps configured `repository_env` and `password_env` values to the tool's standard repository/password environment variables without printing secret values.
- multi-service restore drill suite planning/execution wrapper over the existing single-service restore drill safety model.
- S3-compatible bucket smoke testing through `backup s3-smoke`, using rclone environment config, a unique or supplied test prefix, one generated payload object, download hash verification, prefix listing, and cleanup without writing registry history.
- optional deploy plan `service_id` linking for registered service updates.
- optional service-level `deployment` contracts declaring allowed build adapters/scripts, migration commands, systemd unit actions, and static-site sync targets.
- SQLite-backed audit event table.
- JSONL audit log.
- local state initialization.
- registry consistency checks.
- best-effort read-only server scan for ports, Docker, Caddyfile, and systemd.
- static project analysis for Docker Compose, Docker Compose normalized config when accessible, Dockerfile, Node, PHP/Laravel, Cloudflare/OpenNext, systemd unit files, deploy docs, and `.env` keys.
- generated registry import directories from read-only project analysis, including services, ports, domains, volumes, backups, snapshots, policies, AI rules, and an import report.
- optional observed server drift summaries during registry import generation, including unregistered ports, bind drift, Caddy labels, Docker containers, Docker volumes, and Compose projects.
- read-only generated import readiness checks that validate embedded schemas, registry doctor findings, backup registry consistency, and optional observed drift before promotion.
- generated import production promotion gates that report backup history, repository check, and restore drill readiness for `before_deploy` services.
- approval-token-gated registry import promotion with file-level atomic replacement, active registry file backups, and preservation of active approvals/plans/history directories.
- registry import promotion blocks production `before_deploy` imports until backup history, repository checks, and restore drills are registered as ready.
- read-only observed drift listing/explanation/grouping/suggestions, grouped review YAML export, read-only cleanup planning, plus CLI-only dry-run review apply, ignore, and adoption for explicit port, Caddy domain, Docker container, Compose project, Docker volume, or systemd unit decisions.
- drift adoption credibility metadata with execution-required reason, optional operator note, review status, JSONL adoption journal, incomplete-field warnings, and rollback of prior registry-file writes when a later adopt write fails.
- import overwrite protection that refuses to write over existing generated files unless `--force` is explicit and refuses direct writes over the active registry path.
- import YAML serialization that omits null optional fields so generated files pass strict embedded schema validation.
- deploy plan parsing and minimal draft plan generation.
- built-in policy engine with `passed`, `needs_approval`, and `blocked` results.
- preflight blocking for conflicting ports, domains, Docker names, volumes, protected paths, destructive operations, production migrations, missing production snapshot requirements, unknown plan service ids, existing-service deploy adapter changes outside the service deployment contract, missing ready backup plans, missing/failed/stale registered backup history, and blocked registered snapshot coverage for production services with `backup_policy: before_deploy`.
- configuration-level snapshot creation under the local state directory.
- `tar.zst` registry archive creation with path and symlink safety checks.
- best-effort captured server state and project analysis artifacts.
- database dump and Docker volume artifact capture when explicitly registered and safe.
- snapshot manifest, verification, archive inspection, and rollback plan generation.
- snapshot listing, rollback dry-run inspection, staged registry restore, and approval-token-gated registry restore.
- read-only snapshot manifest inspection by id.
- read-only snapshot coverage reporting for production `before_deploy` services.
- read-only unified deploy gate summary across backup readiness, registered backup history, and registered snapshot coverage.
- deploy dry-run planning through typed operations.
- optional post-deploy health checks through `changes.health.enabled`, covering declared Docker containers, localhost ports, Caddy Host probes, and static-site files.
- fresh preflight re-evaluation before deploy planning.
- stale embedded preflight status blocking.
- production snapshot verification before deploy readiness.
- typed Caddy validate/reload and Docker Compose operation previews.
- package-manager build, Laravel artisan cache/optimize, and systemd service reload/restart deploy adapters.
- safe static-site sync deploy adapter through `changes.static_site.sync`, limited to allowlisted destination roots and no-delete copying.
- read-only Caddyfile managed/unmanaged route inspection.
- optional read-only Caddy `adapt` JSON inspection for normalized HTTP route and host matcher facts.
- Caddyfile import directive graph summaries for exact, snippet, and dynamic/glob imports.
- Caddy adapt route normalization and conflict findings for duplicate or overlapping host/path matchers, including wildcard host, path-prefix, route-priority, matcher summaries, recursive handle chains, route specificity scoring, and TLS automation subject coverage.
- optional loopback-only Caddy Admin API read-only summary through `caddy-routes --admin`.
- generated typed Caddy route snippet file writes through `files.typed` with no raw content passthrough.
- approval record listing, approval, rejection, and expiry checks.
- deploy dry-run readiness when approval scopes cover current `needs_approval` findings.
- local SSH TUI dashboard for services, ports, domains, Docker projects/volumes, observed drift, approvals, snapshots, deploy journals, install findings, and audit tail.
- limited TUI approval actions for approving or rejecting selected pending approval records.
- TUI dashboard deploy gates, backup readiness, backup restore readiness, backup history, snapshot coverage, observed drift, deploy adapter, and registry promotion backup summaries.
- stdio MCP server with safe AI-facing tools.
- MCP tools for reading server context, listing registry facts, inspecting backup doctor, global backup readiness, backup history, snapshot coverage, unified deploy gates, Caddy routes, registry drift list/explain, backup onboarding checks, backup timer plans and monitors, install checks, deploy journals, deploy resume dry-runs, backup dry-run plans, and backup restore dry-run plans, analyzing projects, previewing and checking registry imports, creating draft plans, running preflight, requesting approval, requesting deploy execution approval, listing and inspecting snapshots, and rollback dry-run.
- MCP resources for server context, registry services/ports/domains, Caddy routes, backup doctor, global backup readiness, backup history, snapshot coverage, deploy gates, deploy journals, install checks, audit tail, and safety rules.
- MCP resource templates for targeted service, port, domain, snapshot, deploy journal, and backup dry-run plan reads.
- embedded schema catalog and schema export commands, including `policies.yml` validation.
- MCP schema resources for registry, deploy plan, and approval contracts.
- MCP prompts for safe deploy workflow, blocked preflight response, and approval request summary.
- audit query command with JSONL integrity reporting.
- secret redaction for MCP responses.
- approval request creation.
- SHA-256 checksums for generated snapshot artifacts.
- lightweight audit JSONL integrity warning in server context.
- backup readiness summary in MCP server context.
- backup history summary in MCP server context.
- snapshot coverage summary in MCP server context.
- deploy gates summary in MCP server context.
- preflight snapshot coverage gate for linked production `before_deploy` services.
- backup history stale-target summary in TUI and MCP output.
- snapshot coverage summary in TUI output.
- deploy gates summary in `opsctl status` and TUI output.
- backup readiness, backup history, and snapshot coverage summaries in `opsctl status`.
- policy-backed temporary public data port exceptions with owner, reason, expiry, and mitigation fields.
- timer health monitoring from systemd status, optional journal errors, registered backup/check/drill histories, and deploy-gate blocking after configured consecutive failures.
- controlled deploy execution for typed Caddy route, Caddy validate/reload, Docker Compose up, package-manager build steps, Laravel artisan cache/optimize steps, systemd service reload/restart, allowlisted migration commands, and registry write-back operations.
- controlled deploy execution for safe static-site sync, with marker validation, sensitive-file refusal, symlink refusal, size/count limits, and no arbitrary `rsync --delete`.
- deploy journals record post-deploy health check results and rollback suggestions when health checks fail before registry write-back.
- deploy execution journals under the local state directory.
- read-only deploy journal list/inspect commands and MCP facts.
- dry-run failed deploy journal resume planning through CLI and MCP.
- approval-gated CLI deploy resume execution that writes a new deploy journal.
- CLI helper entry point for executing one typed deploy operation through a sudoers allowlist.
- global lockfile serialization for mutating deploy, snapshot, rollback, backup, helper, and approval commands.
- helper sudoers policy validation with optional `visudo -cf` syntax checks.
- read-only install layout and permission check through `opsctl install-check`, MCP `install_check`, and `opsctl://install/check`.
- Debian install script, `.deb` build scaffolding with opsctl user/group ownership, opt-in full DigitalOcean Docker/Caddy E2E smoke harness, opt-in Debian package install/upgrade/remove regression on VPS, opt-in Debian package install test, release-gate script, release manifest verification, local/multi-arch release packaging script, GitHub Actions CI/release workflows, and integration/security docs.

Full deployment automation is intentionally still limited. `opsctl deploy --execute` only runs opsctl-generated typed operations after a ready dry-run, an approved `deploy_execution` approval record, and the printed approval token. It can execute managed Caddy route writes, generated typed Caddy route snippet writes, Caddy validation/reload, Docker Compose up, safe static-site sync, package-manager build steps, Laravel artisan cache/optimize steps, systemd service reload/restart, exact allowlisted migration commands, optional post-deploy health checks, and registry write-back. Generic raw file writes remain unsupported until they have dedicated typed adapters. Mutating CLI paths acquire a global state lock under the opsctl state directory so concurrent AI tools cannot write registry, journal, snapshot, backup, restore, or approval state at the same time. `opsctl deploy-resume --execute` is CLI-only and requires `deploy-resume --dry-run`, an approved journal-specific `deploy_resume.<journal_id>` approval record, and the printed resume token; it writes a new journal rather than mutating the failed journal. MCP exposes `deploy_resume_dry_run` only and does not expose deploy or resume execution. `request_deploy_execution` only creates an approval request. `opsctl backup readiness`, `opsctl backup plan`, `opsctl backup restore-plan`, `opsctl backup timer plan`, `opsctl backup timer monitor`, `opsctl backup timer alert` without `--execute`, `opsctl backup timer alert-test` without `--execute`, `opsctl backup timer alert-env-template`, `opsctl backup timer alert-configure` without `--execute`, `opsctl backup onboarding-check`, `opsctl deploy-gates`, `opsctl deploy-journals`, `opsctl install-check`, `opsctl caddy-routes`, `opsctl registry normalize` without `--execute`, `opsctl registry drift list`, `opsctl registry drift groups`, `opsctl registry drift suggest`, `opsctl registry drift governance`, `opsctl registry drift review export`, `opsctl registry drift review apply` without `--execute`, `opsctl registry drift cleanup-plan`, `opsctl registry drift cleanup-request export`, `opsctl registry drift cleanup-request verify`, `opsctl registry drift cleanup-request triage`, `opsctl registry drift cleanup-request dashboard`, `opsctl registry drift cleanup-request worklist`, `opsctl registry drift cleanup-request evidence` without `--execute`, `opsctl registry drift cleanup-request execution-plan`, `opsctl registry drift cleanup-request execution-gate`, `opsctl registry drift cleanup-request approval-pack`, `opsctl registry drift cleanup-request volume-ownership`, `opsctl registry drift explain`, `opsctl registry drift service-add` without `--execute`, `opsctl registry drift ignore` without `--execute`, `opsctl registry import-check`, MCP `backup_readiness`, MCP `backup_plan`, MCP `backup_restore_plan`, MCP `backup_timer_plan`, MCP `backup_timer_monitor`, MCP `backup_timer_alert_plan`, MCP `backup_onboarding_check`, MCP `deploy_gates`, MCP `caddy_routes`, MCP `registry_drift_list`, MCP `registry_drift_groups`, MCP `registry_drift_suggest`, MCP `registry_drift_review_export`, MCP `registry_drift_cleanup_plan`, MCP `registry_drift_explain`, MCP `list_deploy_journals`, MCP `deploy_resume_dry_run`, MCP `install_check`, MCP `preview_registry_import`, MCP `check_registry_import`, `opsctl://caddy/routes`, `opsctl://backup/readiness`, `opsctl://backup/plan/{service_id}`, `opsctl://deploy/gates`, `opsctl://deploy/journals`, and `opsctl://install/check` remain dry-run or read-only fact sources. The CLI-only `opsctl backup repo-init --execute --approval-token ...`, `opsctl backup run --execute`, `opsctl backup restore --execute --approval-token ...`, `opsctl backup drill-suite --execute`, `opsctl backup check`, `opsctl backup prune --approval-token ...`, `opsctl backup timer install --execute`, `opsctl backup timer alert --execute`, `opsctl backup timer alert-test --execute`, `opsctl backup timer alert-configure --execute`, `opsctl registry normalize --execute`, `opsctl registry drift service-add --execute`, `opsctl registry drift review apply --execute`, `opsctl registry drift cleanup-request evidence --execute`, `opsctl registry drift ignore --execute`, and `opsctl registry drift adopt --execute` commands execute controlled write paths from registry configuration; MCP does not expose those execution paths. `cleanup-request evidence --execute` only writes `collected_evidence` and `evidence_collected_at` into the review YAML; it does not approve items or clean resources. There is intentionally no drift cleanup execution command; cleanup-request files are review artifacts only, `cleanup-request triage`, `cleanup-request dashboard`, `cleanup-request worklist`, `cleanup-request approval-pack`, and `cleanup-request volume-ownership` summarize unknown/needs_cleanup review work, volume ownership hints, and approval evidence gaps, and `cleanup-request execution-plan` only checks approval/evidence gates without deleting, stopping, pruning, or removing resources. `opsctl backup restore` only restores into a checked staging directory, refuses registered production paths, verifies restored file counts/hash samples/database dump presence, can optionally import plain SQL dumps into isolated no-network Docker containers with `OPSCTL_RESTORE_DB_IMPORT_CHECK=1`, and records restore drill history. `opsctl rollback --restore` requires the approval token printed by `opsctl rollback --dry-run`, restores the registry by default, and restores captured config or Docker volume data only with `--restore-config` or `--restore-data`.

## Quick Start

From this repository:

```bash
cargo build
cargo run -- status
cargo run -- status --json
cargo run -- services
cargo run -- ports
cargo run -- registry validate
cargo run -- registry schemas
cargo run -- registry export-schema services
cargo run -- registry import-projects --output imports/new-registry ~/project-a ~/project-b
cargo run -- registry import-projects --output imports/new-registry --scan-observed ~/project-a ~/project-b
cargo run -- registry import-check imports/new-registry
cargo run -- registry import-check imports/new-registry --scan-observed
cargo run -- registry promote-import imports/new-registry --dry-run
cargo run -- registry promote-import imports/new-registry --approval-token <token>
cargo run -- backup doctor
cargo run -- backup readiness
cargo run -- backup history
cargo run -- backup plan pcafev2 --dry-run
cargo run -- backup run pcafev2
cargo run -- backup run pcafev2 --execute
cargo run -- backup restore-plan pcafev2 --repository-snapshot <snapshot-id> --restore-dir /tmp/opsctl-restore
cargo run -- backup restore pcafev2 --repository-snapshot <snapshot-id> --restore-dir /tmp/opsctl-restore --execute --approval-token <token>
cargo run -- backup check restic-r2-main
cargo run -- backup prune restic-r2-main --approval-token prune:restic-r2-main
cargo run -- backup drill-cleanup
cargo run -- backup timer plan
cargo run -- backup onboarding-check
cargo run -- backup s3-smoke --endpoint s3.us-west-2.idrivee2.com --region us-west-2 --provider IDrive --bucket test-d --execute
cargo run -- deploy-gates
cargo run -- doctor
cargo run -- scan
cargo run -- caddy-routes
cargo run -- caddy-routes --adapt --admin
cargo run -- registry drift list
cargo run -- registry drift explain --code observed_unregistered_port
cargo run -- registry drift adopt --target 127.0.0.1:3000 --service-id pcafev2
cargo run -- analyze /path/to/project
cargo run -- plan /path/to/project --port 3000 --domain example.com
cargo run -- preflight ./deploy-plan.yml
cargo run -- explain-risk ./deploy-plan.yml
cargo run -- snapshot ./deploy-plan.yml --dry-run
cargo run -- snapshot ./deploy-plan.yml
cargo run -- snapshots
cargo run -- snapshot-inspect <snapshot-id>
cargo run -- snapshot-verify <snapshot-id>
cargo run -- snapshot-archive-inspect <snapshot-id>
cargo run -- snapshot-volume-archive-inspect <snapshot-id>
cargo run -- rollback <snapshot-id> --dry-run
cargo run -- rollback <snapshot-id> --stage-dir /tmp/opsctl-restore
cargo run -- rollback <snapshot-id> --restore --approval-token <token>
cargo run -- rollback <snapshot-id> --restore --approval-token <token> --restore-config --restore-data
cargo run -- deploy ./deploy-plan.yml --dry-run --snapshot <snapshot-id>
cargo run -- request-deploy-execution ./deploy-plan.yml --snapshot <snapshot-id> --reason "ready for deploy"
cargo run -- deploy ./deploy-plan.yml --execute --snapshot <snapshot-id> --approval-token <token>
cargo run -- deploy-journals
cargo run -- deploy-journal-inspect <journal-id>
cargo run -- deploy-resume ./deploy-plan.yml --journal <journal-id> --dry-run
cargo run -- request-deploy-resume ./deploy-plan.yml --journal <journal-id> --reason "resume after failed operation"
cargo run -- deploy-resume ./deploy-plan.yml --journal <journal-id> --execute --approval-token <token>
cargo run -- install-check
cargo run -- helper run-deploy-operation ./deploy-plan.yml --operation 4 --snapshot <snapshot-id> --approval-token <token>
cargo run -- helper sudoers-check --path /etc/sudoers.d/opsctl-helper
cargo run -- approvals
cargo run -- audit --limit 20
cargo run -- approve <approval-id>
cargo run -- reject <approval-id> --reason "not safe yet"
cargo run -- tui --dump
cargo run -- tui
cargo run -- mcp
```

By default, the development build uses:

```text
registry: ./examples/server-registry
state:    ./.opsctl
```

Override paths with:

```bash
opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl status
```

Audit records are written to:

```text
.opsctl/opsctl.db
.opsctl/audit.log
```

On Unix systems, `opsctl` sets the state directory to `0700` and state files to `0600`.

## Planned Commands

```bash
opsctl scan
opsctl status
opsctl services
opsctl ports
opsctl registry validate
opsctl registry schemas
opsctl registry export-schema services
opsctl registry import-projects --output imports/new-registry ~/project-a ~/project-b
opsctl registry import-check imports/new-registry
opsctl registry promote-import imports/new-registry --dry-run
opsctl registry promote-import imports/new-registry --approval-token <token>
opsctl backup doctor
opsctl backup readiness
opsctl backup history
opsctl backup plan <service-id> --dry-run
opsctl backup run <service-id>
opsctl backup run <service-id> --execute
opsctl backup restore-plan <service-id> --repository-snapshot <snapshot-id> --restore-dir /tmp/opsctl-restore
opsctl backup restore <service-id> --repository-snapshot <snapshot-id> --restore-dir /tmp/opsctl-restore --execute --approval-token <token>
opsctl backup check <repository-id>
opsctl backup prune <repository-id> --approval-token prune:<repository-id>
opsctl backup s3-smoke --endpoint <endpoint> --region <region> --provider <provider> --bucket <bucket> --execute
opsctl deploy-gates
opsctl caddy-routes
opsctl analyze /path/to/project
opsctl plan /path/to/project --domain example.com
opsctl preflight ./deploy-plan.yml
opsctl snapshot ./deploy-plan.yml
opsctl snapshots
opsctl snapshot-inspect <snapshot-id>
opsctl snapshot-verify <snapshot-id>
opsctl snapshot-archive-inspect <snapshot-id>
opsctl snapshot-volume-archive-inspect <snapshot-id>
opsctl snapshot-coverage
opsctl approvals
opsctl audit --limit 20
opsctl approve <approval-id>
opsctl reject <approval-id> --reason "not safe yet"
opsctl deploy ./deploy-plan.yml --dry-run --snapshot <snapshot-id>
opsctl request-deploy-execution ./deploy-plan.yml --snapshot <snapshot-id> --reason "ready for deploy"
opsctl deploy ./deploy-plan.yml --execute --snapshot <snapshot-id> --approval-token <token>
opsctl deploy-journals
opsctl deploy-journal-inspect <journal-id>
opsctl deploy-resume ./deploy-plan.yml --journal <journal-id> --dry-run
opsctl request-deploy-resume ./deploy-plan.yml --journal <journal-id> --reason "resume after failed operation"
opsctl deploy-resume ./deploy-plan.yml --journal <journal-id> --execute --approval-token <token>
opsctl install-check
opsctl helper run-deploy-operation ./deploy-plan.yml --operation <n> --snapshot <snapshot-id> --approval-token <token>
opsctl helper sudoers-check --path /etc/sudoers.d/opsctl-helper
opsctl rollback <snapshot-id> --dry-run
opsctl rollback <snapshot-id> --stage-dir <dir>
opsctl rollback <snapshot-id> --restore --approval-token <token>
opsctl tui
opsctl tui --dump
opsctl mcp
```

## Repository Layout

```text
DEVELOPMENT.md                8-phase development plan
Cargo.toml                    Rust crate manifest
deny.toml                     cargo-deny dependency policy
src/                          CLI, registry loader, scanner, analyzer, audit store
docs/ARCHITECTURE.md          system architecture and trust boundaries
docs/REGISTRY_SCHEMA.md       registry model and field conventions
docs/PHASE1_REVIEW.md         Phase 1 review notes
docs/PHASE2_REVIEW.md         Phase 2 review notes
docs/PHASE3_REVIEW.md         Phase 3 review notes
docs/PHASE4_REVIEW.md         Phase 4 review notes
docs/PHASE5_REVIEW.md         Phase 5 review notes
docs/PHASE6_REVIEW.md         Phase 6 review notes
docs/PHASE7_REVIEW.md         Phase 7 review notes
docs/PHASE8_REVIEW.md         Phase 8 review notes
docs/PHASE9_REVIEW.md         Phase 9 review notes
docs/PHASE10_REVIEW.md        Phase 10 review notes
docs/PHASE11_REVIEW.md        Phase 11 review notes
docs/PHASE12_REVIEW.md        Phase 12 review notes
docs/PHASE13_REVIEW.md        Phase 13 review notes
docs/PHASE14_REVIEW.md        Phase 14 review notes
docs/PHASE15_REVIEW.md        Phase 15 review notes
docs/PHASE16_REVIEW.md        Phase 16 review notes
docs/PHASE17_REVIEW.md        Phase 17 review notes
docs/PHASE18_REVIEW.md        Phase 18 review notes
docs/PHASE19_REVIEW.md        Phase 19 review notes
docs/PHASE20_REVIEW.md        Phase 20 review notes
docs/PHASE21_REVIEW.md        Phase 21 review notes
docs/PHASE22_REVIEW.md        Phase 22 review notes
docs/PHASE23_REVIEW.md        Phase 23 review notes
docs/PHASE24_REVIEW.md        Phase 24 review notes
docs/PHASE25_REVIEW.md        Phase 25 review notes
docs/PHASE26_REVIEW.md        Phase 26 review notes
docs/PHASE27_REVIEW.md        Phase 27 review notes
docs/PHASE28_REVIEW.md        Phase 28 review notes
docs/PHASE29_REVIEW.md        Phase 29 review notes
docs/PHASE30_REVIEW.md        Phase 30 review notes
docs/PHASE31_REVIEW.md        Phase 31 review notes
docs/PHASE32_REVIEW.md        Phase 32 review notes
docs/PHASE33_REVIEW.md        Phase 33 review notes
docs/PHASE34_REVIEW.md        Phase 34 review notes
docs/PHASE35_REVIEW.md        Phase 35 review notes
docs/PHASE36_REVIEW.md        Phase 36 review notes
docs/PHASE37_REVIEW.md        Phase 37 review notes
docs/PHASE38_REVIEW.md        Phase 38 review notes
docs/PHASE39_REVIEW.md        Phase 39 review notes
docs/PHASE40_REVIEW.md        Phase 40 review notes
docs/PHASE41_REVIEW.md        Phase 41 review notes
docs/PHASE42_REVIEW.md        Phase 42 review notes
docs/PHASE43_REVIEW.md        Phase 43 review notes
docs/PHASE44_REVIEW.md        Phase 44 review notes
docs/PHASE45_REVIEW.md        Phase 45 review notes
docs/PHASE46_REVIEW.md        Phase 46 review notes
docs/PHASE47_REVIEW.md        Phase 47 review notes
docs/PHASE48_REVIEW.md        Phase 48 review notes
docs/PHASE49_REVIEW.md        Phase 49 review notes
docs/PHASE50_REVIEW.md        Phase 50 review notes
docs/PHASE51_REVIEW.md        Phase 51 review notes
docs/PHASE52_REVIEW.md        Phase 52 review notes
docs/PHASE53_REVIEW.md        Phase 53 review notes
docs/PHASE54_REVIEW.md        Phase 54 review notes
docs/PHASE55_REVIEW.md        Phase 55 review notes
docs/PHASE56_REVIEW.md        Phase 56 review notes
docs/PHASE57_REVIEW.md        Phase 57 review notes
docs/PHASE58_REVIEW.md        Phase 58 review notes
docs/PHASE59_REVIEW.md        Phase 59 review notes
docs/PHASE60_REVIEW.md        Phase 60 review notes
docs/PHASE61_REVIEW.md        Phase 61 review notes
docs/PHASE62_REVIEW.md        Phase 62 review notes
docs/PHASE63_REVIEW.md        Phase 63 review notes
docs/PHASE64_REVIEW.md        Phase 64 review notes
docs/PHASE65_REVIEW.md        Phase 65 review notes
docs/PHASE66_REVIEW.md        Phase 66 review notes
docs/PHASE67_REVIEW.md        Phase 67 review notes
docs/PHASE68_REVIEW.md        Phase 68 review notes
docs/PHASE69_REVIEW.md        Phase 69 review notes
docs/PHASE70_REVIEW.md        Phase 70 review notes
docs/PHASE71_REVIEW.md        Phase 71 review notes
docs/PHASE72_REVIEW.md        Phase 72 review notes
docs/PHASE73_REVIEW.md        Phase 73 review notes
docs/PHASE74_REVIEW.md        Phase 74 review notes
docs/PHASE75_REVIEW.md        Phase 75 review notes
docs/PRIVILEGED_HELPER.md     controlled execution helper design
docs/QUALITY.md               quality strategy and test plan
docs/SECURITY.md              operational security guide
docs/AI_INTEGRATION.md        Codex/Claude Code/opencode MCP and CLI integration
docs/DEBIAN_INSTALL.md        Debian install and packaging notes
schemas/*.schema.yml          initial machine-readable schema drafts
examples/server-registry/     sample registry for a single server
scripts/install-debian.sh     simple Debian install helper
scripts/install-sudoers.sh    reviewed sudoers helper policy installer
scripts/test-deb-install.sh   opt-in Debian container install/upgrade/remove test
scripts/e2e-recovery-engine-lab.sh opt-in versioned recovery engine lab
scripts/release-gate.sh       quality, package, Debian, and optional VPS release gate
scripts/release.sh            local release packaging, checksum, and manifest script
scripts/release-verify.sh     release checksum and manifest verification
.github/workflows/ci.yml      CI quality and Debian package regression
.github/workflows/release.yml multi-architecture release packaging workflow
templates/AGENTS.md           template instructions for AI tools
templates/sudoers.opsctl.example
opsctl-idea.html              non-technical concept page
```

## Quality Commands

Current required checks:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo audit
cargo deny check
```

Machine-readable command output is versioned with `schema_version: "opsctl.v1"`.

MCP uses the Model Context Protocol `2025-06-18` stdio shape and exposes only safe tools, resources, resource templates, and prompts. Schema resources are embedded in the binary. `request_approval` and `request_deploy_execution` create requested approval records; they do not approve or execute deployment.

## Core Safety Principles

1. AI can suggest and prepare, but not bypass checks.
2. A deploy plan must be reviewed before execution.
3. Production changes require a ready deploy gate: backup readiness, registered backup history, and registered snapshot coverage must all be acceptable for services that require `before_deploy` backups.
4. Destructive operations require explicit human approval.
5. Docker, Caddy, and systemd access should go through typed operations, not arbitrary shell.
6. Secrets must be redacted from logs, registry examples, and MCP responses.
7. Public traffic should enter through Caddy; application upstreams should prefer `127.0.0.1`.
8. Databases and caches should not be exposed publicly by default.

## Review Checklist

- Do the documents clearly separate goals and non-goals?
- Can a human understand what the registry records?
- Can an AI tool understand that preflight is mandatory?
- Are examples free of raw secrets?
- Are snapshots and rollback represented as first-class concepts?
- Are backup readiness and backup history failures blocked before production deployment?
- Is snapshot coverage visible in the default CLI, TUI, and MCP contexts?
- Is blocked snapshot coverage rejected during preflight for linked production services?
- Is the unified deploy gate available through CLI and MCP before production deployment?
- Are destructive operations blocked unless approved?
- Does the CLI avoid direct deployment execution in this phase?
- Are backup/check/prune and rollback restore paths gated by explicit CLI flags and approval tokens?
- Are audit records written for success and failure paths?
