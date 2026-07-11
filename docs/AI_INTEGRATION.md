# AI Tool Integration

`opsctl` is meant to be the deployment fact source for Codex, Claude Code, opencode, and similar SSH-based AI tools.

## CLI Workflow

Use this workflow when MCP is not configured:

```bash
opsctl status --json
opsctl install-check --json
opsctl deploy-gates --json
opsctl services --json
opsctl ports --json
opsctl registry validate --json
opsctl registry normalize --json
opsctl registry schemas --json
opsctl registry export-schema services --json
opsctl backup doctor --json
opsctl backup readiness --json
opsctl backup history --json
opsctl backup plan <service-id> --dry-run --json
opsctl backup repo-init <repository-id> --json
opsctl backup drill-suite --service <service-id> --restore-root <dir> --json
opsctl backup timer plan --json
opsctl backup onboarding-check --json
opsctl backup s3-smoke --endpoint <endpoint> --region <region> --provider <provider> --bucket <bucket> --json
opsctl registry drift list --json
opsctl registry drift explain --json
opsctl analyze /path/to/project --json
opsctl plan /path/to/project --port 3000 --domain app.example.com > deploy-plan.yml
opsctl preflight deploy-plan.yml --json
opsctl snapshot deploy-plan.yml --json
opsctl snapshot-inspect <snapshot-id> --json
opsctl snapshot-coverage --json
opsctl deploy deploy-plan.yml --dry-run --snapshot <snapshot-id> --json
opsctl deploy-journals --json
opsctl audit --limit 20 --json
```

Stop when preflight returns `blocked`.

Ask the human operator when preflight returns `needs_approval`.

`opsctl registry validate --json` runs embedded JSON Schema validation before typed registry loading. Treat any non-zero `data.schema_errors` as a hard stop before editing deploy plans or registry records.

`opsctl status --json` includes compact deploy gate, backup readiness, registered backup history, and snapshot coverage summaries. Use it for the first health check.

`opsctl install-check --json` is a read-only layout and permission check for the registry and state directories. Treat `data.ok: false` as a hard stop before relying on local facts.

`opsctl deploy-gates --json` is the deploy-before-you-touch-anything summary. It combines backup readiness, registered backup history, and registered snapshot coverage for production services with `backup_policy: before_deploy`. Treat `status: "blocked"` as a hard stop before production deployment. It does not run backups, create snapshots, restore data, or print secret values.

When the deploy gate is blocked or a production plan is being prepared, call `opsctl backup readiness --json`, `opsctl backup history --json`, `opsctl snapshot-coverage --json`, or `opsctl backup plan <service-id> --dry-run --json` for details.

When updating an existing registered service, read the service's `deployment` contract in `services.yml`. Production build steps, migration commands, systemd actions, and static-site sync targets should match that contract. Preflight blocks existing-service adapter changes that are outside the contract.

When reviewing a generated registry import, do not treat schema success alone as production readiness. `opsctl registry import-check <dir> --json` reports `production_gates`; `opsctl registry promote-import <dir> --dry-run` blocks production `before_deploy` services until backup history, repository check history, and restore drill history are ready.

`opsctl snapshot-coverage --json` reports whether registered production `before_deploy` services have a registered snapshot with the required scope. Treat `blocked` coverage as a hard stop before production deployment; preflight also blocks linked production `before_deploy` services when registered snapshot coverage is not ready.

`opsctl backup plan <service-id> --dry-run --json` returns Restic command previews and required environment variable names. It does not execute Restic, create dumps, initialize repositories, or print environment variable values.

`opsctl backup repo-init <repository-id> --json` previews repository initialization and prints the approval token for a human-reviewed CLI execution. Use it only after storage smoke testing and credential review. Do not run `--execute` from MCP or an autonomous AI workflow.

`opsctl backup drill-suite --service <service-id> --restore-root <dir> --json` previews restore drills for one or more services and reports per-service blockers. Execution is CLI-only, uses the same staging restore safety model as `backup drill`, and should run only after real backup history exists.

`opsctl backup s3-smoke` is CLI-only storage onboarding. Without `--execute` it previews the S3-compatible smoke test. With `--execute` it writes, reads, lists, and deletes one generated object under a test prefix using rclone, with sanitized diagnostics. Do not treat this as backup readiness; production gates still require real backup history, repository check history, and restore drill history.

When a deploy plan modifies an existing registered service, set `service_id` in the plan. Production mutating plans linked to services with `backup_policy: before_deploy` must pass backup dry-run readiness, registered backup history freshness, and registered snapshot coverage during preflight.

## MCP Workflow

Phase 108–121 recovery execution, profile-draft writes, key lifecycle changes, signing, checkpoints, archive export/drill execution, retention import, backfill recording, governance installation, reconciliation, and bundle writes remain CLI-only. AI clients may additionally read `recovery_qualification`, `evidence_backfill_plan`, `evidence_retention_status`, `evidence_archive_drill_status`, `evidence_key_dr_status`, and `recovery_slo`; MCP has no recovery-container, profile-write, signature-write, approval, archive-write, timer-enable, or cleanup-deletion authority. Current backfill claims require an explicit cleanup-request path, and historical Phase 95 counts remain labeled as historical.

Run the local stdio MCP server:

```bash
opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl --actor codex mcp
```

Expose only this command to the MCP client. Do not expose Docker, Caddy, systemctl, or shell tools as equivalent capabilities.

Available MCP tools:

- `read_server_context`
- `list_services`
- `list_ports`
- `list_domains`
- `backup_doctor`
- `backup_readiness`
- `backup_history`
- `snapshot_coverage`
- `deploy_gates`
- `caddy_routes`
- `registry_drift_list`
- `registry_drift_explain`
- `install_check`
- `list_deploy_journals`
- `inspect_deploy_journal`
- `deploy_resume_dry_run`
- `backup_plan`
- `backup_onboarding_check`
- `backup_timer_plan`
- `analyze_project`
- `create_deploy_plan`
- `preflight_deploy_plan`
- `request_approval`
- `request_deploy_execution`
- `list_snapshots`
- `verify_snapshot`
- `inspect_snapshot_archive`
- `inspect_snapshot`
- `rollback_dry_run`
- `volume_protect_failure_matrix`
- `volume_protect_gap_rescan`
- `evidence_audit_verify`
- `recovery_qualification`
- `evidence_backfill_plan`
- `evidence_retention_status`
- `evidence_archive_drill_status`
- `evidence_key_dr_status`
- `recovery_slo`

Available MCP resources:

- `opsctl://server/context`
- `opsctl://registry/services`
- `opsctl://registry/ports`
- `opsctl://registry/domains`
- `opsctl://backup/doctor`
- `opsctl://backup/readiness`
- `opsctl://backup/history`
- `opsctl://snapshot/coverage`
- `opsctl://deploy/gates`
- `opsctl://caddy/routes`
- `opsctl://deploy/journals`
- `opsctl://install/check`
- `opsctl://audit/tail`
- `opsctl://safety/rules`
- `opsctl://schemas`

Available MCP resource templates:

- `opsctl://registry/service/{service_id}`
- `opsctl://registry/port/{port}`
- `opsctl://registry/domain/{host}`
- `opsctl://snapshot/{snapshot_id}`
- `opsctl://backup/plan/{service_id}`
- `opsctl://deploy/journal/{journal_id}`
- `opsctl://schema/{name}`

Available MCP prompts:

- `safe_deploy_workflow`
- `preflight_blocked_response`
- `approval_request_summary`

## Client Configuration Pattern

Use the client-specific MCP configuration format, but keep the command equivalent to:

```json
{
  "command": "opsctl",
  "args": [
    "--registry",
    "/srv/server-registry",
    "--state-dir",
    "/var/lib/opsctl",
    "--actor",
    "codex",
    "mcp"
  ]
}
```

Use a different `--actor` value for Claude Code or opencode so the audit log shows which tool made each request.

## Required Agent Rules

Agents should follow this order:

1. Call `read_server_context` and inspect `deploy_gates`, `backup_readiness`, `backup_history`, and `snapshot_coverage` in the returned context.
2. Read `opsctl://install/check`, `opsctl://safety/rules`, and `opsctl://registry/ports` if resources are supported. Use MCP `caddy_routes`, resource `opsctl://caddy/routes`, or CLI `opsctl caddy-routes --json` when Caddyfile route ownership is relevant. Use MCP `registry_drift_list` / `registry_drift_explain` or CLI `opsctl registry drift list --json` before adopting observed resources into the registry.
3. Call `analyze_project` for the target project.
4. Create or inspect a deploy plan. If it updates a registered service, include `service_id`.
5. If it updates a registered service, compare the plan's adapter sections with the service's `deployment` contract.
6. Call `preflight_deploy_plan`.
7. If status is `blocked`, stop.
8. If status is `needs_approval`, call `request_approval` or ask the human to create one.
9. For production services, inspect the unified deploy gate first. Use MCP `deploy_gates`, MCP resource `opsctl://deploy/gates`, or CLI `opsctl deploy-gates --json`.
10. For production services, inspect backup readiness and registered backup history details when the deploy gate is blocked or unclear. Use MCP `backup_readiness`, `backup_history`, `backup_doctor`, and `backup_plan`; MCP resources `opsctl://backup/readiness`, `opsctl://backup/history`, `opsctl://backup/doctor`, and `opsctl://backup/plan/{service_id}`; or CLI `opsctl backup readiness`, `opsctl backup history`, `opsctl backup doctor`, and `opsctl backup plan <service-id> --dry-run`. Preflight blocks linked `before_deploy` services when a backup plan or registered backup history is not ready.
11. For production services, inspect snapshot coverage details when the deploy gate is blocked or unclear. Use MCP `snapshot_coverage`, MCP resource `opsctl://snapshot/coverage`, or CLI `opsctl snapshot-coverage --json`. Preflight blocks linked `before_deploy` services when registered snapshot coverage is not ready.
12. Create and verify a snapshot before production deployment. Use MCP `inspect_snapshot`, MCP resource `opsctl://snapshot/{snapshot_id}`, or CLI `opsctl snapshot-inspect <snapshot-id> --json` to read the manifest. Then use MCP `verify_snapshot` or CLI `opsctl snapshot-verify <snapshot-id> --json` to confirm declared artifact checksums, MCP `inspect_snapshot_archive` or CLI `opsctl snapshot-archive-inspect <snapshot-id> --json` to inspect registry archive members, and CLI `opsctl snapshot-volume-archive-inspect <snapshot-id> --json` when Docker volume archives are present.
13. Use CLI dry-run deploy inspection before execution. MCP can request deploy execution approval, but execution itself must happen outside MCP.
14. After CLI execution, read `opsctl deploy-journals --json`, MCP `list_deploy_journals`, or `opsctl://deploy/journals`; inspect the latest journal before making further changes. If a CLI deploy failed, use MCP `deploy_resume_dry_run` or CLI `opsctl deploy-resume ./deploy-plan.yml --journal <journal-id> --dry-run --json` to understand whether the failed journal can be safely resumed. Resume execution requires CLI `request-deploy-resume`, human approval, and `opsctl deploy-resume --execute`; do not execute recovery steps from MCP.

When a client supports resource templates, prefer targeted reads such as `opsctl://registry/port/3000`, `opsctl://registry/service/caddy`, `opsctl://deploy/journal/<journal_id>`, or `opsctl://backup/plan/caddy` before proposing a conflicting deploy plan.

`opsctl://server/context` also includes `deploy_gates`, `backup_readiness`, `backup_history`, and `snapshot_coverage`, so clients can see the global backup and rollback state before calling dedicated tools/resources.

Use `opsctl://schemas` and `opsctl://schema/{name}` when generating registry YAML or deploy plans. Schema names are `services`, `ports`, `domains`, `volumes`, `snapshots`, `backups`, `policies`, `plans`, and `approvals`.

`opsctl://schema/{name}` returns `name`, `file_name`, and the parsed JSON Schema object. It never accepts a filesystem path.

`opsctl analyze` may include Docker Compose normalized config when `docker compose config --format json` is available. The normalized result keeps service names, image/build presence, ports, volumes, env file paths, and environment key names only; environment values are redacted and must not be treated as retrievable secrets.

## Safety Notes

MCP does not expose:

- arbitrary shell
- Docker remove
- Docker volume delete
- Docker system prune
- Caddy overwrite
- deploy execution
- deploy resume execution
- helper execution
- backup execution
- backup timer install
- registry drift adoption
- rollback execution
- approve/reject

`request_approval` only creates a requested approval record. A human still runs `opsctl approve` or `opsctl reject`.

Preflight may evaluate backup readiness, registered backup history freshness, and registered snapshot coverage, but it uses dry-run planning and registry records only. It does not execute Restic/rustic, create database dumps, inspect remote repositories, create snapshots, prune repositories, or restore data.

MCP `deploy_gates` and `opsctl://deploy/gates` are read-only/dry-run summaries. They combine existing fact sources and do not execute deployment, backup, snapshot, restore, prune, check, or database dump commands.

MCP `install_check` and `opsctl://install/check` are read-only layout checks. They do not create directories, change permissions, write registry files, or execute deployment.

MCP `list_deploy_journals`, `inspect_deploy_journal`, `opsctl://deploy/journals`, and `opsctl://deploy/journal/{journal_id}` are read-only local journal reads. They do not resume or execute deployment.

MCP `request_deploy_execution` creates a requested `deploy_execution` approval record only after a ready deploy dry-run. It does not run `opsctl deploy --execute`, does not call `opsctl helper`, and redacts execution-token-like fields from MCP output. A human operator should re-run CLI dry-run, review the execution token, approve the request if appropriate, and execute through CLI/helper.

MCP `backup_readiness` and `backup_plan` have the same boundary: they return dry-run reports only. They never execute Restic/rustic or database dump commands.

MCP `backup_onboarding_check`, `backup_timer_plan`, and `backup_timer_alert_plan` are read-only/dry-run planning tools. They do not run backup jobs, repository checks, restore drills, `systemctl enable`, alert delivery, alert sink configuration, or registry promotion. CLI `opsctl backup timer alert-status` may include an `activation_plan` with safe command-shaped guidance and environment-variable names, but it never prints secret target values or sends notifications. CLI `opsctl backup timer alert`, `opsctl backup timer alert-test`, and `opsctl backup timer alert-configure` are also dry-run unless `--execute` is supplied; these execute paths are intentionally CLI-only.

CLI and MCP deploy-gate reports can include `blocked_reason`, `blocked_details`, `backup_history_target_issues`, and `remediation_commands`. AI clients should treat those commands as human-review hints. Reading deploy gates never runs backup, check, restore drill, Docker, Caddy, systemd, or cleanup commands.

MCP `registry_drift_list`, `registry_drift_groups`, `registry_drift_suggest`, `registry_drift_review_export`, `registry_drift_cleanup_plan`, `registry_drift_cleanup_evidence_plan`, `registry_drift_volume_evidence_plan`, and `registry_drift_explain` are read-only observed-drift views. CLI `opsctl registry normalize` without `--execute`, `opsctl registry drift governance`, `opsctl registry drift ownership`, `opsctl registry drift review export`, `opsctl registry drift cleanup-plan`, `opsctl registry drift cleanup-request export`, `opsctl registry drift cleanup-request verify`, `opsctl registry drift cleanup-request triage`, `opsctl registry drift cleanup-request approval-pack`, `opsctl registry drift cleanup-request evidence-plan`, `opsctl registry drift cleanup-request volume-ownership`, and `opsctl registry drift cleanup-request execution-plan` are also dry-run/read-only helpers for registry formatting and batching human review. These paths do not adopt or ignore ports, domains, Caddy sites, Docker resources, systemd units, volumes, or service definitions, and cleanup planning never generates destructive commands. Drift review exports may include ownership evidence, service candidates, cleanup risk, exact-match requirements, and resource fingerprints; AI tools should treat those as review aids, not ownership proof. Cleanup request files are review artifacts only; `cleanup-request sync` can show `diff_summary`, `added_items`, and `removed_stale_items` before writing a synchronized review file, and still only writes the review YAML when `--execute` is explicitly supplied. `cleanup-request triage` summarizes unknown/needs_cleanup ownership work and approval evidence gaps, while `cleanup-request approval-pack` packages selected items with evidence gaps, safety notes, and human approval command templates without writing or cleaning anything. `cleanup-request evidence-plan` and MCP `registry_drift_volume_evidence_plan` expose Docker volume evidence groups, batch planning, backup snapshot gaps, and restore drill gaps without collecting evidence, approving cleanup, or executing removal. `cleanup-request volume-ownership` narrows that review to Docker volumes and groups anonymous hash volumes, named volumes, attached containers, service candidates, and missing backup/restore proof without approving or cleaning anything. `cleanup-request execution-plan` checks evidence gates such as exact resource id, approval expiry, maintenance window, rollback plan, backup snapshot, and restore drill proof. Cleanup runbooks explicitly mark steps as unsafe to automate and requiring separate destructive approval. CLI `cleanup-request request-execution` and `cleanup-request execute --execute` are not exposed through MCP; the execute path only records an approved manual handoff after a fresh current-drift exact-match check and still does not delete, stop, prune, or mutate observed resources. Registry normalization execution, service skeleton creation, review apply, ignore, and adoption remain CLI-only and dry-run by default. CLI `registry normalize --execute` only rewrites registry YAML into schema-compatible normalized form and does not change service ownership. CLI `registry drift service-add --execute` only creates an empty service target for later adoption and requires a human reason. CLI review apply execution uses the same checked single-item ignore/adopt paths, requires the human-edited review file to contain reasons/expiry/service ownership where needed, and writes the same JSONL journals. CLI ignore execution requires a human reason and expiry, writes `drift-ignores.jsonl`, and only records an exception. CLI adoption execution requires a human reason, can include an operator note and review status, writes `drift-adoptions.jsonl`, and still does not prove ownership by itself.

MCP `caddy_routes` is read-only. It can summarize Caddyfile import directives without reading imported file contents. With `adapt: true`, it can summarize `caddy adapt` JSON route/TLS conflicts, matcher kinds, recursive handler chains, and conservative route priority facts. With `admin: true`, it can read `GET /config/` only from a loopback Caddy Admin API endpoint and returns counts/summaries, not the full config. Its `management` summary can recommend typed snippet or marker-based review paths, but it reports that Admin API writes are unsupported. It never writes Caddy config or reloads Caddy.

The backup resources have the same boundary. `opsctl://backup/readiness` and `opsctl://backup/plan/{service_id}` are dry-run resource reads and never execute Restic/rustic, database dumps, prune, check, or restore commands.

CLI backup execution is separate from MCP. `opsctl backup run <service-id> --execute` runs only planner-generated database dump and Restic/rustic commands after the plan is ready, records a local history entry, and avoids persisting stdout/stderr contents. `opsctl backup check` is controlled execution. `opsctl backup prune` requires the explicit approval token printed by the command.

CLI backup restore is also separate from MCP. `opsctl backup restore-plan <service-id> --repository-snapshot <id> --restore-dir <dir>` previews a Restic/rustic restore into a staging directory and prints the approval token. `opsctl backup restore ... --execute --approval-token <token>` never restores directly over registered production paths.

Deploy plans may use typed adapter sections for `changes.build.steps`, `changes.laravel`, and `changes.systemd.units`. These adapters generate allowlisted argv only; do not put raw shell commands into deploy plans.

MCP `backup_history` and `opsctl://backup/history` read registered backup result history, repository check history, and restore drill history from `backups.yml`. They do not inspect a remote repository or execute backup commands while being read. A production `before_deploy` service should be treated as blocked when the latest backup, latest repository check, or latest restore drill is missing, failed, future-dated, invalid, stale, or has limitations.

MCP `snapshot_coverage` and `opsctl://snapshot/coverage` only read registered snapshot records and count local snapshot directories. They do not create snapshots, inspect archive contents, restore data, or prove that a snapshot artifact is restorable.

MCP `inspect_snapshot`, CLI `opsctl snapshot-inspect`, and MCP `opsctl://snapshot/{snapshot_id}` only read local snapshot manifests through an allowlisted snapshot id. They do not restore files, extract archives, validate archive contents, or execute rollback.

MCP `verify_snapshot` and CLI `opsctl snapshot-verify` are read-only checksum checks for declared local artifacts. They do not extract archives, validate archive member contents, restore files, execute rollback, or prove database/application consistency.

MCP `inspect_snapshot_archive` and CLI `opsctl snapshot-archive-inspect` stream the verified local registry archive and check tar member path/type/size limits. They do not extract files, restore data, write archive contents to disk, or execute rollback.

CLI `opsctl snapshot-volume-archive-inspect` performs the same read-only archive safety checks for captured Docker volume archives. CLI `opsctl rollback --stage-dir` extracts the verified registry archive into a new staging directory only. CLI `opsctl rollback --restore --approval-token <token>` can replace the registry from a verified snapshot after dry-run conflict checks; Caddy config and Docker volume data restore require explicit `--restore-config` or `--restore-data` flags and should still be reviewed by a human.

## Phase 97-107 cleanup evidence tools

MCP `registry_drift_cleanup_evidence_resolve`, `registry_drift_cleanup_workflow`, `volume_protect_history`, `volume_protect_run_status`, `volume_protect_campaign_status`, `volume_protect_metrics`, and `registry_drift_cleanup_manifest_status` are read-only. They preview exact evidence matches, lifecycle/campaign health, OpenMetrics content, and sealed-manifest validity. MCP never performs live repository verification and does not expose volume-protect run/resume/batch/campaign/cleanup/journal maintenance, handoff-pack writes, reconciliation writes, or `cleanup-request evidence-resolve --execute`.

CLI `cleanup-request evidence-resolve` only writes evidence for a current Docker volume when one fresh exact evidence pair is available and the current bounded content fingerprint still matches. `--verify-repository` additionally invokes the configured Restic/rustic client read-only to require the referenced snapshot and exact cleanup-request/volume tags. `backup volume-protect run --execute` is CLI-only, accepts only an unmounted volume without a service candidate, restores into a non-overlapping staging path, and enforces the requested database verification strength. Campaigns remain serial and stop at configured capacity, duration, and failure bounds. A sealed handoff manifest is bound to the request hash and expiry; reconciliation only journals items confirmed absent by current drift and never performs deletion.

If a backup target sets `max_age_hours`, treat `stale_targets > 0` as a production blocker. This is a local freshness policy over registered history, not proof that the remote backup repository is recoverable.
