# opsctl Development Plan

`opsctl` 是一个轻量的单机服务器部署安全闸门。它不做公网控制面板，不替代 Docker、Caddy、systemd，也不把服务器改造成 PaaS。它的职责是让 Codex、Claude Code、opencode 等 AI 工具在部署前先读取服务器现状、生成部署计划、通过安全检查，并在需要时请求人工审批。

目标服务器是 Debian 13，基础组件包括 Docker CE、Docker Compose、Caddy，以及多个不同技术栈项目。第一版使用 Rust 开发，输出一个本地单二进制工具。

## 1. Product Goal

### Core Goal

让 AI 工具可以参与部署，但不能绕过服务器的安全边界。

`opsctl` 必须做到：

- 记录服务器已有服务、端口、域名、Caddy 路由、Docker Compose 项目、容器名、Docker volume、数据目录、备份位置。
- 在新项目部署前执行 preflight，发现冲突或危险操作时阻断。
- 在生产变更前创建快照，保证有明确的回滚入口。
- 给人提供本地 TUI，给 AI 工具提供本地 stdio MCP。
- 所有敏感操作必须有审计记录，危险操作必须人工审批。

### Non-Goals

第一版明确不做：

- 不做公网 Web 控制面板。
- 不直接复刻 Coolify、Dokku、CapRover、Dokploy、Portainer。
- 不让 AI 直接持有 Docker socket、Caddy 写权限或任意 root shell。
- 不接管所有部署流程。
- 不把服务器状态只放在 prompt 或说明文档里。
- 不把 `.env`、数据库连接串、API key 暴露给 MCP 输出或日志。

## 2. Architecture

### High-Level Shape

```text
Codex / Claude Code / opencode
        |
        | stdio MCP / CLI
        v
     opsctl
        |
        | registry + preflight + approvals + snapshots
        v
  controlled Docker / Caddy / systemd helper
```

### Binary Commands

第一版目标命令：

```bash
opsctl scan
opsctl status
opsctl services
opsctl ports
opsctl analyze /path/to/project
opsctl plan /path/to/project --domain example.com
opsctl preflight ./deploy-plan.yml
opsctl backup plan <service-id> --dry-run
opsctl backup run <service-id> --execute
opsctl backup check <repository-id>
opsctl backup prune <repository-id> --approval-token <token>
opsctl snapshot ./deploy-plan.yml
opsctl snapshot-verify <snapshot-id>
opsctl snapshot-archive-inspect <snapshot-id>
opsctl snapshot-volume-archive-inspect <snapshot-id>
opsctl approve <approval-id>
opsctl deploy ./deploy-plan.yml --dry-run --snapshot <snapshot-id>
opsctl request-deploy-execution ./deploy-plan.yml --snapshot <snapshot-id> --reason "ready for deploy"
opsctl deploy ./deploy-plan.yml --execute --snapshot <snapshot-id> --approval-token <token>
opsctl deploy-journals
opsctl deploy-journal-inspect <journal-id>
opsctl install-check
opsctl helper run-deploy-operation ./deploy-plan.yml --operation <n> --snapshot <snapshot-id> --approval-token <token>
opsctl rollback <snapshot-id> --dry-run
opsctl rollback <snapshot-id> --stage-dir <new-dir>
opsctl rollback <snapshot-id> --restore --approval-token <token>
opsctl tui
opsctl mcp
```

### Local Files

建议默认路径：

```text
/etc/opsctl/
  config.yml
  policies.yml
  sudoers.example

/srv/server-registry/
  AGENTS.md
  services.yml
  ports.yml
  domains.yml
  volumes.yml
  snapshots.yml
  backups.yml
  approvals/
  plans/
  history/

/var/lib/opsctl/
  opsctl.db
  snapshots/
  cache/

/var/log/opsctl/
  audit.log
```

YAML 作为人可读登记簿，SQLite 作为查询和历史索引。两者冲突时，以 registry + audit log 为准，`opsctl doctor` 负责检测漂移。

## 3. Data Model

### Service

```yaml
id: pcafev2
name: P.Cafe
root: /home/ivmm/daohang/pcafev2
kind: nextjs
deploy_method: docker-compose-and-node
environment: production
owner: ivmm
status: active
ports:
  - 39800
  - 55432
domains:
  - p.cafe
compose_projects:
  - pcafev2
containers:
  - pcafe-db
volumes:
  - pcafe-pg-data
data_paths: []
backup_policy: before_deploy
```

### Deploy Plan

AI 工具不能直接执行部署命令，应该先生成计划。

```yaml
id: deploy_20260704_001
actor: codex
project_root: /home/ivmm/daohang/pcafev2
intent: deploy
environment: production
changes:
  ports:
    reserve:
      - 39800
      - 55432
  caddy:
    routes:
      - host: p.cafe
        upstream: 127.0.0.1:39800
  docker:
    compose_project: pcafev2
    containers:
      - pcafe-db
    volumes:
      - pcafe-pg-data
  files:
    write:
      - /etc/caddy/Caddyfile
  migrations:
    required: true
  destructive_ops: []
preflight:
  status: pending
```

### Snapshot

快照必须回答三个问题：部署前是什么状态，部署中会改什么，失败后如何恢复。

```yaml
id: snap_20260704_001
plan_id: deploy_20260704_001
created_at: 2026-07-04T01:50:00+08:00
scope:
  - registry
  - caddy
  - docker_metadata
  - compose_files
  - database_dump
  - volume_manifest
artifacts:
  registry_archive: /var/lib/opsctl/snapshots/snap_20260704_001/registry.tar.zst
  caddy_config: /var/lib/opsctl/snapshots/snap_20260704_001/Caddyfile
  docker_state: /var/lib/opsctl/snapshots/snap_20260704_001/docker-state.json
  rollback_plan: /var/lib/opsctl/snapshots/snap_20260704_001/rollback.yml
status: complete
```

## 4. Safety Rules

### Always Block Unless Approved

- `rm -rf` targeting project roots, `/srv`, `/var/lib/docker`, database paths, backup paths, Caddy configs, or registered data directories.
- `docker compose down -v`
- `docker volume rm`
- `docker system prune`
- removing or recreating registered production containers.
- overwriting `.env`, production compose files, Caddyfile, systemd units.
- running production migrations without a recent successful snapshot.
- binding database/cache ports to `0.0.0.0` unless explicitly approved.
- reusing existing port, domain, route, container name, compose project, or volume.

### Default Safe Bias

- Public traffic should enter through Caddy.
- Application upstreams should prefer `127.0.0.1`.
- Databases and Redis should not be exposed publicly.
- AI-facing MCP output must redact secrets.
- Dry-run/preflight must be available for every deploy action.

## 5. Rust Stack

Recommended crates:

```text
CLI: clap
TUI: ratatui + crossterm
MCP: rmcp or official Model Context Protocol Rust SDK
Config: serde + serde_yaml + toml
DB: rusqlite or sqlx sqlite
Docker metadata: docker compose config --format json first, bollard later
Caddy API: reqwest
Logs: tracing + tracing-subscriber
Errors: anyhow + thiserror
Archives: tar + zstd
Time: time or chrono
Policy: internal rules first; optional OPA/Rego/CUE later
```

Do not fully reimplement Docker Compose parsing in phase 1. Prefer:

```bash
docker compose config --format json
```

Then validate the normalized output.

## 6. Project Compatibility

The scanner must recognize at least these categories:

- Docker Compose projects.
- Dockerfile-only projects.
- Next.js / React / Node projects.
- Laravel / PHP / Composer projects.
- Static build output projects.
- Caddy reverse proxy routes.
- Cloudflare Workers / OpenNext / external deployments.
- systemd services.

External deployments such as Cloudflare Workers or Zeabur should still be registered, even when they do not consume local ports. This prevents the tool from wrongly assuming a project is undeployed.

## 7. Eight Development Phases

### Phase 1: Product Spec And Registry Foundation

Goal: define the source of truth and the safety vocabulary.

Deliverables:

- `README.md` explaining what `opsctl` is and is not.
- `docs/ARCHITECTURE.md`
- `docs/REGISTRY_SCHEMA.md`
- initial YAML schemas for services, ports, domains, volumes, snapshots, backups, plans, approvals.
- sample registry under `examples/server-registry/`.
- first `AGENTS.md` template for Codex / Claude / opencode.

Implementation:

- No real deployment execution.
- Focus on schema, terminology, examples, and redaction rules.
- Define stable IDs for services, plans, snapshots, and approvals.

Acceptance:

- A human can read examples and understand how to register an existing server.
- An AI tool can read `AGENTS.md` and know it must call `opsctl preflight` before deployment.
- Secrets are never represented as raw values in examples.

Risks:

- Over-designing schema before real scanner feedback.
- Mixing "desired state" and "observed state" too early.

### Phase 2: Rust CLI Skeleton And Local State

Goal: produce a working Rust binary with local config, registry loading, and basic output.

Deliverables:

- Rust workspace.
- `opsctl status`
- `opsctl services`
- `opsctl ports`
- `opsctl doctor`
- SQLite local state initialization.
- structured audit log writer.

Implementation:

- `clap` for commands.
- `serde_yaml` for registry files.
- `rusqlite` or `sqlx` for local cache/history.
- `tracing` for logs.
- all commands support `--json`.

Acceptance:

- `opsctl status --json` returns machine-readable state.
- invalid registry files produce clear errors.
- audit log records command, actor, timestamp, target, result.

Risks:

- Logging sensitive data.
- Making the database authoritative too early.

### Phase 3: Scanner And Project Analyzer

Goal: read existing server state and project deployment hints.

Deliverables:

- `opsctl scan`
- `opsctl analyze /path/to/project`
- scanners for:
  - open TCP/UDP ports via `ss`.
  - Caddy config and Caddy admin API when available.
  - Docker Compose normalized config when accessible.
  - Dockerfile `EXPOSE`.
  - package scripts for Node/Bun/pnpm/npm.
  - Composer/Laravel indicators.
  - Cloudflare/OpenNext/Wrangler indicators.
  - systemd service files.

Implementation:

- Docker access is best-effort. If Docker socket is unavailable, report limited visibility instead of failing silently.
- `.env` scanning only extracts variable names, never values.
- classify detected project type and risk hints.

Acceptance:

- For known projects, analyzer can detect likely ports, compose files, Dockerfiles, package manager, database/cache dependencies, and deployment docs.
- Analyzer can identify hard-coded `container_name`, volumes, and host port mappings.
- Output clearly separates "detected" from "registered".

Risks:

- False confidence when Docker access is denied.
- Reading secret values by mistake.

### Phase 4: Preflight And Policy Engine

Goal: block unsafe deploy plans before execution.

Deliverables:

- `opsctl plan`
- `opsctl preflight ./deploy-plan.yml`
- `opsctl explain-risk ./deploy-plan.yml`
- internal policy engine.
- severity levels: `info`, `warn`, `needs_approval`, `blocked`.

Policies:

- port already used.
- domain or route already registered.
- Caddy upstream conflicts.
- duplicate Docker container name.
- duplicate Docker volume.
- production migration without snapshot.
- public database/cache exposure.
- destructive Docker commands.
- writes to protected paths.
- missing rollback plan.

Implementation:

- Start with built-in Rust policies.
- Keep policy input/output as JSON so OPA/Rego or CUE can be added later.
- Make every policy produce a human-readable explanation and a machine-readable code.

Acceptance:

- A conflicting plan fails before any change is made.
- A risky but valid plan returns `needs_approval`.
- A safe plan returns `passed`.
- JSON output can be consumed by MCP.

Risks:

- Building a command denylist instead of deployment-aware checks.
- Making warnings too noisy and training users to ignore them.

### Phase 5: Snapshot And Rollback Foundation

Goal: create a useful restore point before production changes.

Deliverables:

- `opsctl snapshot ./deploy-plan.yml`
- `opsctl snapshots`
- `opsctl rollback <snapshot-id> --dry-run`
- snapshot manifest format.
- rollback plan format.

Snapshot scope:

- registry files.
- Caddy config and adapted JSON when available.
- Docker metadata: containers, images, networks, volumes, compose projects.
- normalized compose files involved in the plan.
- service process/port state.
- database logical dump when configured.
- volume manifest and optional archive for small volumes.
- filesystem manifest for protected paths.

Implementation:

- Use `tar.zst` for config snapshots.
- Use logical database dumps first; full VM/block snapshots are outside first version.
- Large volume backup can be metadata-only unless service policy requires full backup.
- Snapshot must be created before deploy execution when plan affects production.

Acceptance:

- `rollback --dry-run` explains exact restore steps.
- failed snapshot blocks production deploy.
- snapshot artifacts are indexed and auditable.
- secrets are either excluded or encrypted, never printed.

Risks:

- Claiming rollback is complete when only config was captured.
- Backups that cannot be restored.
- Long-running backups blocking small low-risk changes.

### Phase 6: Controlled Execution And Privileged Helper

Goal: execute only approved, preflight-passed deploy plans.

Deliverables:

- `opsctl deploy ./deploy-plan.yml`
- privileged helper design.
- sudoers allowlist example.
- dry-run execution engine.
- Caddy validate/reload integration.
- Docker Compose execution wrapper.

Execution rules:

- No plan execution without matching preflight result.
- No production execution without snapshot when required.
- Any `needs_approval` item must have a valid approval record.
- Every command runs through a typed operation, not arbitrary shell text.

Implementation:

- Represent actions as operations:
  - `ReservePort`
  - `WriteCaddyRoute`
  - `ValidateCaddy`
  - `ReloadCaddy`
  - `ComposeUp`
  - `RunMigration`
  - `WriteRegistry`
  - `CreateSystemdUnit`
- avoid passing raw shell from AI to helper.
- store stdout/stderr with secret redaction.

Acceptance:

- Deployment refuses stale preflight results.
- Caddy reload is validated before activation.
- Docker Compose project name is explicit.
- audit log shows each operation and result.

Risks:

- The helper becoming a general root shell.
- Too much sudo permission.
- Partial deployments without transaction records.

### Phase 7: TUI And Human Approval Flow

Goal: make the tool understandable and usable over SSH.

Deliverables:

- `opsctl tui`
- views:
  - dashboard.
  - services.
  - ports.
  - domains/Caddy routes.
  - Docker projects/volumes.
  - pending plans.
  - approvals.
  - snapshots/rollback.
  - audit history.
- approval workflow.

Implementation:

- `ratatui` + `crossterm`.
- TUI reads the same registry/state as CLI.
- TUI never requires a daemon or web server.
- actions should show exact diff and risk reason before approval.

Acceptance:

- user can see what will change before approving.
- user can reject a dangerous request.
- pending approvals expire.
- TUI can open snapshot details and rollback dry-run.

Risks:

- Making TUI too much like a control panel.
- Hiding important details behind pretty UI.

### Phase 8: MCP, Hardening, And Release

Goal: expose safe AI-facing tools and prepare first usable release.

Deliverables:

- `opsctl mcp`
- MCP tools:
  - `read_server_context`
  - `list_services`
  - `list_ports`
  - `list_domains`
  - `analyze_project`
  - `create_deploy_plan`
  - `preflight_deploy_plan`
  - `request_approval`
  - `list_snapshots`
  - `rollback_dry_run`
- install script.
- Debian packaging notes.
- security guide.
- integration guide for Codex, Claude Code, opencode.
- end-to-end demo with sample projects.

MCP rules:

- Default to read-only.
- No direct Docker remove, volume delete, system prune, arbitrary shell, or Caddy overwrite tools.
- All outputs redact secrets.
- Deploy execution via MCP should only submit or reference approved plans; direct execution can be disabled by config.

Hardening:

- file permissions review.
- secret redaction tests.
- approval expiry.
- audit log tamper warning.
- checksum snapshots.
- protected path denylist.

Acceptance:

- Codex/Claude/opencode can query state and run preflight through MCP.
- AI cannot execute destructive operations without approval.
- release binary can be installed on a fresh Debian server.
- documented recovery path exists for failed deploy.

Risks:

- MCP exposing too much operational power.
- AI treating warnings as permission to continue.
- release process skipping permission setup.

### Phase 9: MCP Context Resources And Audit Query

Goal: make `opsctl` easier for AI clients to consume as a context source without increasing execution power.

Deliverables:

- `opsctl audit --limit <n>`
- MCP `resources/list`
- MCP `resources/read`
- MCP `prompts/list`
- MCP `prompts/get`
- resources for server context, registry facts, audit tail, and safety rules.
- prompts for safe deployment workflow, blocked preflight explanation, and approval summaries.

Safety rules:

- MCP resources are strict `opsctl://` allowlist entries.
- No arbitrary file resource is exposed.
- Resource reads and prompt gets are audited.
- Audit query skips invalid JSONL rows but reports integrity warnings.
- This phase still does not add deploy execution, rollback execution, approve, reject, Docker delete, Caddy overwrite, or shell tools.

Acceptance:

- AI clients can discover server context through resources, not only tools.
- AI clients can get operator-facing deployment prompts.
- Humans can query recent audit events from the CLI.
- Existing MCP tools remain compatible.

### Phase 10: MCP Resource Templates And Targeted Lookups

Goal: let AI clients read specific registry or snapshot records without loading full registry files.

Deliverables:

- MCP `resources/templates/list`
- `opsctl://registry/service/{service_id}`
- `opsctl://registry/port/{port}`
- `opsctl://registry/domain/{host}`
- `opsctl://snapshot/{snapshot_id}`

Safety rules:

- Template values are single URI path segments.
- Template values reject slashes, backslashes, parent traversal, and unsupported characters.
- No `file://` resources are exposed.
- Unknown resource URIs return JSON-RPC resource-not-found errors.
- Template resource reads are audited through `mcp:resources/read`.
- This phase still does not add deploy execution, rollback execution, approval decisions, Docker deletion, Caddy overwrite, or arbitrary shell.

Acceptance:

- AI clients can discover supported templates.
- AI clients can fetch one service, port, domain, or snapshot manifest by id.
- Rejected URI schemes are audited.

### Phase 11: Registry Schema Exposure And Validation

Goal: make the registry contract discoverable from the installed binary and from MCP.

Deliverables:

- `opsctl registry validate`
- `opsctl registry schemas`
- `opsctl registry export-schema <name>`
- embedded schema catalog compiled into the binary.
- MCP `opsctl://schemas`
- MCP `opsctl://schema/{name}`

Safety rules:

- Schema names are strict allowlist values.
- Schema export reads embedded static schema text, not filesystem paths.
- `registry validate` reuses the existing registry loader and doctor checks.
- This phase does not perform JSON Schema validation with a third-party validator yet.
- This phase still does not add deploy execution, rollback execution, approval decisions, Docker deletion, Caddy overwrite, or arbitrary shell.

Acceptance:

- An installed `opsctl` binary can export schemas without needing the source tree.
- AI clients can inspect registry and deploy-plan schema contracts through MCP.
- Invalid schema names are rejected before lookup.

### Phase 12: Strict Registry JSON Schema Validation

Goal: make `opsctl registry validate` enforce the embedded registry schemas before typed loading and doctor consistency checks.

Deliverables:

- Draft 2020-12 validation for registry YAML files.
- validation for `services.yml`, `ports.yml`, `domains.yml`, `volumes.yml`, `snapshots.yml`, and `backups.yml`.
- structured schema findings with file, schema name, instance path, schema path, and message.
- `registry validate --json` combines schema errors and doctor findings without breaking the existing `data.errors` field.
- `jsonschema` dependency with default network/file resolver features disabled.

Safety rules:

- Schema validation uses embedded schemas only.
- No schema path argument is accepted.
- JSON Schema reference resolution over HTTP or filesystem is not enabled.
- Doctor checks run only after schema validation succeeds.
- This phase still does not add deploy execution, rollback execution, approval decisions, Docker deletion, Caddy overwrite, or arbitrary shell.

Acceptance:

- The example registry passes embedded schema validation.
- Invalid registry YAML fails before typed registry loading.
- AI clients receive stable JSON fields for schema validation findings.

### Phase 13: Restic Backup Adapter Dry-Run

Goal: make backup requirements explicit before deployment without implementing a backup engine inside `opsctl`.

Deliverables:

- `backups.yml` registry file.
- `schemas/backups.schema.yml`.
- `opsctl backup doctor`.
- `opsctl backup plan <service-id> --dry-run`.
- Restic command argv previews for backup, forget/prune, and check.
- required environment variable name reporting without printing values.
- database dump placeholders that document output paths without executing dump commands.

Safety rules:

- No Restic command is executed in this phase.
- No backup repository is initialized or modified.
- No environment variable values are read into output.
- Backup paths must be absolute and must not contain parent traversal.
- Missing Restic environment variables block a backup plan but remain warning-level in backup doctor.
- This phase still does not add deploy execution, restore execution, Docker deletion, Caddy overwrite, approval decisions, or arbitrary shell.

Acceptance:

- The example registry includes backup repositories and targets.
- Backup registry YAML passes strict schema validation.
- AI clients can inspect a dry-run backup plan before proposing a production deployment.
- `opsctl backup plan` refuses to run without `--dry-run`.

### Phase 14: Deploy Preflight Backup Readiness Gate

Goal: make production deploy preflight verify that registered services with `backup_policy: before_deploy` have a ready backup dry-run plan.

Deliverables:

- optional `service_id` field on deploy plans.
- `schemas/plans.schema.yml` support for `service_id`.
- preflight service resolution from explicit `service_id`, project root, compose project, containers, volumes, Caddy routes, domains, and reserved ports.
- blocking `backup_plan_not_ready` finding when a linked production service requires before-deploy backups but its dry-run plan is not ready.
- blocking `unknown_plan_service` finding when a plan references a service id not present in the registry.
- warning `backup_service_unresolved` finding when a production mutating plan cannot be linked to a registered service.

Safety rules:

- No backup command is executed in this phase.
- No deployment command is executed in this phase.
- Backup readiness is checked through `plan_backup(... dry_run: true)` only.
- Existing new-project plans without an inferable registered service receive a warning instead of a hard block.

Acceptance:

- A registered production service with missing Restic environment variables blocks preflight before deployment.
- A safe new production plan remains compatible when it does not target an existing registered service.
- Unknown explicit `service_id` values block with a focused finding.
- AI guidance tells clients to set `service_id` when modifying a registered service.

### Phase 15: MCP Backup Dry-Run Tools

Goal: let AI clients query backup readiness through MCP without exposing backup execution.

Deliverables:

- MCP `backup_doctor` tool.
- MCP `backup_plan` tool with required `service_id`.
- `backup_plan` always calls `plan_backup(... dry_run: true)`.
- MCP audit records for both backup tools.
- blocked backup plans are audited with `decision: deny`.
- tool list, docs, and AI guidance include the backup tools.

Safety rules:

- MCP does not expose backup execution, Restic execution, repository prune, repository check execution, database dump execution, or restore.
- `backup_plan` validates `service_id` before registry lookup.
- Tool results pass through the existing recursive redaction layer.
- Environment variable names may be returned; values must not be printed or persisted.

Acceptance:

- `tools/list` includes `backup_doctor` and `backup_plan`.
- `tools/call backup_doctor` returns a structured backup doctor report.
- `tools/call backup_plan` returns a structured dry-run backup plan for a service.
- MCP audit log records backup tool calls with correct decision, target, risk, and dry-run metadata.

### Phase 16: MCP Backup Resources

Goal: make backup readiness discoverable through MCP resources while keeping the same allowlist and dry-run boundaries.

Deliverables:

- `opsctl://backup/doctor` resource.
- `opsctl://backup/plan/{service_id}` resource template.
- service id validation reused for backup plan tools and resources.
- resource read audit risk metadata for backup plan resources.
- resource read audit `dry_run: true` for backup plan resources.
- docs and AI guidance for backup resource reads.

Safety rules:

- No `file://` or arbitrary filesystem resource is exposed.
- `opsctl://backup/plan/{service_id}` validates `service_id` before registry lookup.
- Backup plan resource reads call `plan_backup(... dry_run: true)` only.
- Resource output passes through recursive redaction.
- Failed backup plan resource reads are audited as denied errors.

Acceptance:

- `resources/list` includes `opsctl://backup/doctor`.
- `resources/templates/list` includes `opsctl://backup/plan/{service_id}`.
- `resources/read opsctl://backup/doctor` returns a structured backup doctor report.
- `resources/read opsctl://backup/plan/<service>` returns a structured dry-run backup plan.
- unsafe backup plan resource ids are rejected and audited.

### Phase 17: Global Backup Readiness Summary

Goal: provide one dry-run fact source for all production services that require `backup_policy: before_deploy`.

Deliverables:

- `backup_readiness(registry)` core report.
- `opsctl backup readiness`.
- MCP `backup_readiness` tool.
- `opsctl://backup/readiness` resource.
- readiness aggregation for required and missing environment variable names.
- service-level readiness summaries with target counts and limitations.
- audit metadata: high risk, dry-run, deny when readiness is blocked.

Safety rules:

- No backup command is executed.
- No Restic command is executed.
- No database dump command is executed.
- No repository is initialized, pruned, checked, restored, or modified.
- Only production services with `backup_policy: before_deploy` are checked.
- Environment variable names may be reported; values must not be printed or persisted.

Acceptance:

- `opsctl backup readiness --json` returns versioned JSON.
- blocked readiness exits non-zero and is audited as dry-run.
- MCP `backup_readiness` returns the same structured readiness report.
- `opsctl://backup/readiness` returns the same structured readiness report.
- tests cover CLI, MCP tool, MCP resource, and core readiness logic.

### Phase 18: Backup Readiness In Default Context And TUI

Goal: surface backup readiness in the first places humans and AI clients normally inspect.

Deliverables:

- `read_server_context` includes `backup_readiness`.
- `opsctl://server/context` includes `backup_readiness`.
- TUI dump summary includes backup readiness fields.
- TUI dashboard renders backup readiness status.
- contract tests cover server context, server context resource, and TUI dump.

Safety rules:

- Still no backup execution.
- Context and TUI only call the dry-run readiness aggregator.
- Environment variable names may appear; values must not be printed or persisted.
- TUI remains read-only.

Acceptance:

- MCP `read_server_context` returns backup readiness status.
- MCP `opsctl://server/context` returns backup readiness status.
- `opsctl tui --dump --json` returns backup readiness summary fields.
- TUI unit test verifies backup readiness summary loading.

### Phase 19: Backup History Fact Source

Goal: let humans and AI clients inspect registered backup result history before deployment without executing any backup command.

Deliverables:

- `backups.yml` supports a `history` array for externally produced backup results.
- backup registry schema validates history records.
- `backup_doctor` validates history record references to services, targets, and repositories.
- `backup_history(registry)` core report.
- `opsctl backup history`.
- MCP `backup_history` tool.
- `opsctl://backup/history` resource.
- `read_server_context` includes `backup_history`.
- TUI dump summary and dashboard include backup history fields.
- contract tests cover CLI, MCP tool, MCP resource, server context, and TUI dump.

Safety rules:

- Still no backup execution.
- History records are registered facts, not proof that opsctl inspected a remote repository.
- No Restic, Borg, rustic, Bupstash, Kopia, or database dump command is executed.
- History output must not contain secret values.
- Missing or failed latest history blocks the history summary, but does not mutate registry or state.

Acceptance:

- `opsctl backup history --json` returns versioned JSON.
- missing successful history exits non-zero and is audited.
- MCP `backup_history` returns the same structured report.
- `opsctl://backup/history` returns the same structured report.
- MCP `read_server_context` returns backup history status.
- `opsctl tui --dump --json` returns backup history summary fields.

### Phase 20: Backup History Freshness Policy

Goal: let humans and AI clients detect stale registered backup history before deployment without executing backup tools or inspecting remote repositories.

Deliverables:

- `backups.yml` backup targets support optional `max_age_hours`.
- backup registry schema validates `max_age_hours`.
- `backup_history_at(registry, now_utc)` core report for deterministic freshness checks.
- `backup_history(registry)` applies freshness checks against current UTC time.
- backup history reports include:
  - `services_ready`
  - `services_blocked`
  - `freshness_policy_targets`
  - `stale_targets`
  - `future_records`
  - `invalid_timestamps`
- `backup_doctor` reports invalid history timestamps.
- TUI dump summary and dashboard include stale target count.
- contract tests cover freshness fields in CLI, MCP, server context, and TUI dump.

Safety rules:

- Still no backup execution.
- Still no remote repository inspection.
- `max_age_hours` is a local policy over registered history records only.
- Future timestamps, invalid timestamps, stale latest records, and missing successful records block backup history status.
- No secret values are read, printed, or persisted.

Acceptance:

- Stale latest successful history blocks `backup_history_at` in deterministic unit tests.
- Invalid history timestamps are reported by `backup_doctor`.
- `opsctl backup history --json` includes freshness counters.
- MCP `backup_history` and `opsctl://backup/history` include freshness counters.
- `opsctl tui --dump --json` includes `backup_history_stale_targets`.

### Phase 21: Preflight Backup History Gate

Goal: make production mutating preflight block when registered `before_deploy` backup history is missing, failed, stale, future-dated, or invalid.

Deliverables:

- `check_backup_plan` also evaluates `backup_history(registry)` for affected services.
- `backup_history_ready` info finding for registered services with ready backup history.
- `backup_history_not_ready` blocked finding for missing, failed, stale, future-dated, or invalid registered backup history.
- CLI contract coverage where backup dry-run planning is ready but backup history still blocks preflight.

Safety rules:

- Still no backup execution.
- Still no remote repository inspection.
- Still no registry or state write-back during preflight.
- Preflight only reads registry-backed history and the existing dry-run planner.

Acceptance:

- Preflight blocks linked production services with `backup_policy: before_deploy` when registered backup history is not ready.
- A plan-ready/history-failed fixture proves the backup plan gate and backup history gate are separate.
- Versioned JSON findings expose stable `backup_history_ready` and `backup_history_not_ready` codes.

### Phase 22: CLI Status Backup Summary

Goal: make `opsctl status` useful as the first CLI fact source for backup readiness and registered backup history.

Deliverables:

- `opsctl status --json` includes backup readiness summary fields.
- `opsctl status --json` includes backup history summary fields.
- human-readable `opsctl status` output includes compact backup readiness and history lines.
- CLI contract test covers the new status JSON fields.

Safety rules:

- Still no backup execution.
- Still no remote repository inspection.
- Status only reuses the existing dry-run backup readiness report and registered history report.
- Status does not write registry or backup state; it still follows the normal audit-record path used by CLI commands.
- A blocked backup summary does not make `opsctl status` fail; detailed deploy blocking remains in preflight.

Acceptance:

- `opsctl status --json` exposes stable backup summary fields for AI clients.
- `opsctl status` remains a low-risk fact command.
- Backup status details remain available through `opsctl backup readiness`, `opsctl backup history`, and per-service `opsctl backup plan <service-id> --dry-run`.

### Phase 23: Snapshot Coverage Report

Goal: let humans and AI clients see whether registered production `before_deploy` services have enough registered snapshot coverage before deployment.

Deliverables:

- `snapshot_coverage(registry, state_dir)` core report.
- `opsctl snapshot-coverage`.
- service-level required snapshot scope calculation.
- blocked findings for missing snapshots, incomplete snapshots, missing required scope, invalid snapshot timestamps, and registered snapshot limitations.
- CLI contract test for example snapshot coverage gaps.

Safety rules:

- Still no snapshot creation.
- Still no restore execution.
- Still no backup execution.
- Still no Docker volume archive or database dump execution.
- The report reads registry snapshot records and local snapshot manifests only.

Acceptance:

- `opsctl snapshot-coverage --json` returns versioned JSON.
- Missing snapshot records block the coverage report.
- Registered snapshot limitations block the coverage report.
- Local snapshot count is reported without treating unregistered local snapshots as service coverage.

### Phase 24: Snapshot Coverage Default Context

Goal: surface snapshot coverage in the first places humans and AI clients normally inspect.

Deliverables:

- `opsctl status --json` includes snapshot coverage summary fields.
- human-readable `opsctl status` includes a compact snapshot coverage line.
- `opsctl tui --dump --json` includes snapshot coverage summary fields.
- TUI dashboard renders snapshot coverage status.
- MCP `read_server_context` includes full `snapshot_coverage`.
- MCP `snapshot_coverage` tool and `opsctl://snapshot/coverage` resource expose the same report.

Safety rules:

- Still no snapshot creation.
- Still no restore execution.
- Still no backup execution.
- MCP snapshot coverage is read-only and does not expose filesystem paths beyond existing registry facts.
- A blocked snapshot coverage summary does not make `opsctl status` or TUI dump fail; production gating remains in preflight and deploy dry-run.

Acceptance:

- CLI status, TUI dump, MCP server context, MCP tool, and MCP resource all expose snapshot coverage.
- MCP `snapshot_coverage` calls are audited.
- The report remains read-only and versioned through existing `opsctl.v1` and MCP response wrappers.

### Phase 25: Preflight Snapshot Coverage Gate

Goal: make production mutating preflight block when registered `before_deploy` snapshot coverage is missing, incomplete, missing required scope, invalid, or limited.

Deliverables:

- Registry-only snapshot coverage aggregation for policy checks.
- `evaluate_preflight` checks snapshot coverage for linked production services with `backup_policy: before_deploy`.
- `snapshot_coverage_ready` info finding for linked services with ready registered coverage.
- `snapshot_coverage_not_ready` blocked finding for linked services with missing or blocked registered coverage.
- CLI contract coverage where backup readiness and registered backup history are ready, but snapshot coverage still blocks preflight.

Safety rules:

- Still no snapshot creation.
- Still no restore execution.
- Still no backup execution.
- Preflight only reads registry-backed snapshot records for this gate.
- Local unregistered snapshot directories never satisfy the gate.
- Finding messages summarize counts and status without echoing artifact paths or raw limitation text.

Acceptance:

- Linked production `before_deploy` services with blocked snapshot coverage make preflight status `blocked`.
- Backup readiness, backup history, and snapshot coverage gates are independent.
- Versioned JSON findings expose stable `snapshot_coverage_ready` and `snapshot_coverage_not_ready` codes.

### Phase 26: Unified Deploy Gates Fact Source

Goal: give humans and AI clients one before-deploy status command that combines backup readiness, registered backup history, and registered snapshot coverage.

Deliverables:

- `opsctl deploy-gates`.
- `deploy_gates(registry, state_dir)` core report.
- MCP `deploy_gates` tool.
- MCP `opsctl://deploy/gates` resource.
- `read_server_context` includes `deploy_gates`.
- CLI and MCP contract tests for blocked gate output and audit metadata.
- docs and AGENTS guidance for using the deploy gate before production plans.

Safety rules:

- Still no deployment execution.
- Still no backup execution.
- Still no snapshot creation or restore execution.
- The report summarizes counts and service gate status only.
- The report must not echo backup secret values, raw environment values, backup artifact paths, or snapshot artifact paths.
- Blocked deploy gates are audited with high risk and dry-run metadata.

Acceptance:

- `opsctl deploy-gates --json` returns versioned JSON and exits non-zero when any gate is blocked.
- MCP `deploy_gates` returns the same structured report.
- MCP `opsctl://deploy/gates` returns the same structured report.
- MCP server context exposes the deploy gate summary for first-read AI clients.
- Audit records show blocked gates as `decision: deny`, `risk: high`, and `dry_run: true`.

### Phase 27: Deploy Gates In Default CLI And TUI Contexts

Goal: make the unified before-deploy gate visible in the default human entry points, not only in the dedicated command and MCP context.

Deliverables:

- `opsctl status --json` includes compact `deploy_gates_*` summary fields.
- human-readable `opsctl status` includes a compact `deploy_gates` line.
- `opsctl tui --dump --json` includes compact `deploy_gates_*` summary fields.
- TUI dashboard renders a compact deploy gates line.
- CLI contract and TUI unit tests cover the new default-context fields.
- docs explain that this is a read-only visibility phase.

Safety rules:

- Still no deployment execution.
- Still no backup execution.
- Still no snapshot creation or restore execution.
- Default contexts reuse already-computed backup readiness, backup history, and snapshot coverage reports.
- A blocked deploy gate does not make `opsctl status` or `opsctl tui --dump` fail; the dedicated `opsctl deploy-gates` command and preflight remain the enforcement surfaces.

Acceptance:

- `opsctl status --json` exposes stable deploy gate summary fields.
- `opsctl tui --dump --json` exposes stable deploy gate summary fields.
- The TUI dashboard shows the deploy gate status without printing secret values, backup env names, or artifact paths.

### Phase 28: Snapshot Inspect CLI And MCP Tool

Goal: let humans and AI clients inspect one local snapshot manifest through stable read-only interfaces before rollback planning.

Deliverables:

- `opsctl snapshot-inspect <snapshot-id>`.
- `snapshot::inspect_snapshot_report(state_dir, snapshot_id)` core report.
- MCP `inspect_snapshot` tool.
- CLI and MCP contract tests for successful inspect and audit metadata.
- unsafe snapshot ids are rejected before path construction.
- docs and AGENTS guidance explain that inspect is read-only and does not restore data.

Safety rules:

- Still no restore execution.
- Still no backup execution.
- Still no snapshot creation through inspect.
- Snapshot ids must match the existing `snap_...` allowlist.
- Manifest reads use the existing limited regular-file, no-symlink path.
- Rollback plan availability is checked without following symlinks.

Acceptance:

- `opsctl snapshot-inspect <snapshot-id> --json` returns versioned JSON with `read_only: true`.
- MCP `inspect_snapshot` returns the same structured inspect report.
- Invalid snapshot ids are rejected and audited.
- Inspect output does not execute or imply rollback.

## 8. Testing Strategy

### Unit Tests

- YAML schema parsing.
- secret redaction.
- policy rules.
- deploy plan validation.
- snapshot manifest generation.
- protected path matching.

### Integration Tests

- sample Docker Compose project with port conflict.
- Caddy config validation with fake route.
- `.env` scan only returns keys.
- Docker access denied scenario.
- snapshot creation and rollback dry-run.

### End-To-End Tests

Use disposable fixtures:

```text
fixtures/
  nextjs-basic/
  laravel-compose/
  static-site/
  caddy-existing-route/
  postgres-volume/
```

Each fixture should have expected preflight results.

## 9. Security Baseline

### Users And Permissions

Recommended deployment model:

```text
ivmm              human operator
ai-deploy         AI tool user, low privilege
opsctl-helper     privileged helper, only callable through sudoers allowlist
```

`ai-deploy` should not be in the `docker` group. Docker group access is effectively root.

### Sudoers Principle

Allow:

```text
ai-deploy -> /usr/local/bin/opsctl helper <typed-operation>
```

Do not allow:

```text
ai-deploy -> /bin/bash
ai-deploy -> /usr/bin/docker *
ai-deploy -> /usr/bin/rm *
ai-deploy -> /usr/bin/systemctl *
```

### Redaction

Never print raw values for keys matching:

```text
*_SECRET
*_TOKEN
*_KEY
PASSWORD
DATABASE_URL
REDIS_URL
VALKEY_URL
POSTGRES_URL
MYSQL_*
R2_SECRET_ACCESS_KEY
```

## 10. First Release Definition

`v0.1` is successful when:

- existing projects can be registered.
- current ports and known services can be displayed.
- project analyzer can detect likely deployment risks.
- deploy plans can be preflighted.
- production deploy is blocked without snapshot.
- TUI can show pending risks and approvals.
- MCP can expose read-only server context and preflight.

`v0.1` does not need to fully automate every deployment. It only needs to reliably prevent unsafe deployment.

## 11. Open Questions

- Should registry YAML be the primary source of truth, with SQLite as cache, or should SQLite become primary after v0.1?
- Should full Docker volume backup be opt-in per service because volume sizes may be large?
- Should production database dumps be handled by service-specific adapters or generic commands?
- Should Caddy be managed through Caddyfile snapshots, Admin API, or both?
- Should `opsctl deploy` be disabled by default for MCP clients?
- Should remote storage for snapshots be built in, or left to user-managed backup tools first?

## 12. Suggested Next Step

Start Phase 1 by creating the schema and examples. Avoid writing Docker/Caddy execution code until the registry, plan format, and preflight model are stable.

The guiding rule for all phases:

```text
AI can suggest and prepare. opsctl checks and records. The human approves risky changes.
```
