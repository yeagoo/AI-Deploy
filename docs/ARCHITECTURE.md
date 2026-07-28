# Architecture

`opsctl` is a local deployment safety gate. It sits between AI tools and server operations.

```text
Codex / Claude Code / opencode
        |
        | CLI / stdio MCP
        v
     opsctl
        |
        | registry + policies + snapshots + approvals
        v
 typed Docker / Caddy / systemd operations
```

## Design Position

The tool should remain small and local.

It should not introduce:

- a public web UI
- a long-lived network API by default
- a second platform to maintain
- broad Docker socket access for AI tools
- arbitrary shell access for AI tools

The main job is to answer:

1. What is already deployed?
2. What will this plan change?
3. Can it conflict with something already running?
4. Does it touch production data?
5. Is there a snapshot and rollback path?
6. Does a human need to approve this?

## Components

### CLI

The CLI is the primary automation interface.

Expected users:

- human operator
- deployment scripts
- AI coding tools through shell calls

Important commands:

```bash
opsctl status --json
opsctl analyze /path/to/project --json
opsctl preflight ./deploy-plan.yml --json
opsctl snapshot ./deploy-plan.yml
```

### TUI

The TUI is for local SSH sessions.

It should show:

- services
- ports
- domains and routes
- Docker projects and volumes
- pending deploy plans
- required approvals
- snapshots and rollback records
- audit history

The TUI is not a web panel and should not require a browser, login system, or exposed port.

### MCP Server

The MCP server exposes safe tools to AI clients over stdio.

Default MCP posture:

- read-only context is allowed
- project analysis is allowed
- plan creation is allowed
- preflight is allowed
- approval requests are allowed
- direct deployment can be disabled by config
- destructive Docker or shell operations are never exposed directly

Example MCP tool names:

```text
read_server_context
list_services
list_ports
list_domains
backup_doctor
backup_readiness
backup_history
backup_plan
analyze_project
create_deploy_plan
preflight_deploy_plan
request_approval
list_snapshots
rollback_dry_run
```

Example MCP resource names:

```text
opsctl://server/context
opsctl://backup/doctor
opsctl://backup/readiness
opsctl://backup/history
opsctl://backup/plan/{service_id}
opsctl://registry/service/{service_id}
opsctl://registry/port/{port}
opsctl://snapshot/{snapshot_id}
```

`opsctl://server/context` includes backup readiness and registered backup history summaries so AI clients do not need to guess whether production backups are ready before planning a deployment.

### Registry

The registry is the human-readable source of truth.

Suggested location:

```text
/srv/server-registry/
```

It records expected server facts: services, reserved ports, routes, volumes, data paths, snapshots, backup repositories, backup targets, registered backup result history, and approvals.

### Local State Database

SQLite stores cache and history.

Suggested location:

```text
/var/lib/opsctl/opsctl.db
```

The registry remains readable without SQLite. SQLite should improve lookup, history, and audit views, but should not hide the source of truth from humans.

### Privileged Helper

The helper runs only typed operations after preflight and approval.

It must not become a generic shell.

Allowed operation examples:

```text
ValidateCaddy
ReloadCaddy
ComposeConfig
ComposeUp
CreateSnapshot
WriteRegistry
CreateSystemdUnit
```

Disallowed as direct AI operations:

```text
docker volume rm
docker system prune
docker compose down -v
rm -rf
arbitrary bash
raw systemctl *
```

## Trust Boundaries

### AI Tool Boundary

AI tools may:

- read non-secret context
- analyze project files
- propose a deploy plan
- run preflight
- request approval

AI tools may not:

- bypass preflight
- get unredacted secrets
- delete files or volumes directly
- write Caddy config directly
- access Docker socket directly
- run arbitrary root commands

### Docker Boundary

Docker group access is effectively root. The recommended `ai-deploy` user should not be in the Docker group.

Docker state can be read through a controlled path. Deployment should be executed by typed `opsctl` operations after checks pass.

### Caddy Boundary

Caddy is the public entry point. Route changes can break existing production sites.

Route changes should go through:

1. plan
2. preflight
3. snapshot of current config
4. validation
5. approval when needed
6. reload
7. audit record

Host prerequisites use a separate fail-closed read path. `host-edge inspect` reads only fixed OS/tool/Caddy/listener/firewall facts. `host-edge plan` has two enum-like stages: `prepare_caddy`, then `expose_https`. It accepts no package name, public port list, firewall command, systemctl action, shell, or raw file content. The exposure stage is not ready until the Registry owns the service/domain/upstream, the exact `/etc/caddy/Caddyfile` managed route validates, the loopback upstream accepts TCP, no non-Caddy process owns 80/443, `INPUT` begins with an unconditional jump to a terminal-DROP `OPSCTL-INPUT`, and `netfilter-persistent.service` is enabled for the fixed `/etc/iptables/rules.v4` format. Its fixed ordering activates Caddy when necessary and re-verifies listeners, route, and upstream before any firewall operation.

Remote bootstrap is a separate CLI-only controller boundary for upgrading `opsctl` itself when the installed version cannot self-upgrade. A private typed manifest supplies one explicit IPv4 target, SSH user, pinned identity/known-hosts hashes, and exact prior/new amd64 Debian artifacts. Plan collects bounded version, install-check, and exact sudo-policy evidence. Execute re-plans, requires one exact approval, snapshots both packages under private local state, transfers only digest-derived filenames, promotes them into a fixed root-owned staging directory, re-hashes before fixed `dpkg`, and journals every transition. Failed install attempts restore the exact prior artifact; later rollback requires a separate journal-specific approval. No generic remote command, file, path, password, MCP, helper, or sudoers-template surface is created.

Prior-package recovery is the read-only bootstrap precursor when the exact old package exists only in a retained root backup. The caller provides a timestamp-shaped backup id and expected hash, not a remote path. The controller reads only the fixed checksum manifest, accepts one safe matching `opsctl_*_amd64.deb` member, and streams it to a create-new private local path. It does not list directories, create target files, or treat a locally rebuilt same-version package as equivalent.

Host-edge mutation remains CLI-only and is not exported through MCP or the privileged helper. Each stage has one separate approval scope whose record must exactly equal the reviewed scope/constraint set and bind the current evidence hash, stage, and execution token. Read-only evidence commands and privileged commands use bounded fixed environments. Execution reruns the plan, requires effective uid 0, requires the private state tree to be owned by that effective identity, captures create-new Caddyfile/firewall/state evidence, then writes a bounded journal after every operation. Caddy installation binds the inspected APT candidate and invokes exact `caddy=<version>`; the other fixed adapters invoke only `/usr/bin/systemctl`, `/usr/sbin/iptables`, and `/usr/sbin/iptables-save` without a shell.

Rollback uses a separate journal-specific approval identity and token. It checks snapshot hashes, Registry/current evidence, installed package-version drift, Caddyfile drift, and exact firewall-rule counts. It deletes only rules recorded as inserted by that journal and verifies the resulting service/package/file/rule state. The full firewall snapshot is evidence only; automatic whole-firewall restore is forbidden because it could erase concurrent SSH/security changes.

## Data Flow

### Read Flow

```text
registry files
  + observed ports from ss
  + Docker metadata when accessible
  + Caddy config/API when accessible
  + project analyzers
        |
        v
normalized server context
        |
        v
CLI / TUI / MCP
```

### Deployment Flow

```text
AI proposes deploy plan
        |
        v
opsctl preflight
        |
        +--> blocked
        +--> needs approval
        +--> passed
                |
                v
          opsctl snapshot
                |
                v
          typed operations
                |
                v
          registry update + audit log
```

### Authorized Git Push Flow

```text
trusted Git/CI runner updates reviewed worktree
        |
        v
exact commit + branch -> opsctl project deliver
        |
        +--> immutable Git/source verification
        +--> constrained automation authorization match
        +--> current backup/restore/preflight gates
        +--> complete verified snapshot
        +--> typed deploy + health + terminal result
```

opsctl does not expose a public webhook listener or perform repository checkout. The trusted runner owns authentication and worktree update; opsctl independently verifies the resulting commit, branch, origin fingerprint, cleanliness, authorization constraints, and production gates before mutation.

### Rollback Flow

```text
snapshot manifest
        |
        v
checksum verify
        |
        v
archive inspect
        |
        v
rollback dry-run
        |
        v
human approval when destructive
        |
        v
restore selected config/data/routes
```

## Snapshot Model

Snapshots are deployment restore points. They are not always full machine images.

A practical snapshot can include:

- registry archive
- Caddy config
- Docker metadata
- normalized compose files
- service port state
- database logical dump when configured
- Docker volume manifest
- protected path file manifest
- rollback plan

The snapshot manifest must state what was captured and what was not captured. A partial snapshot must not be presented as a full rollback guarantee.

## Failure Philosophy

When uncertain, `opsctl` should prefer blocking or asking for approval.

Examples:

- Docker socket unavailable: report limited visibility.
- Caddy API unavailable: fall back to config file if readable; otherwise mark route visibility incomplete.
- `.env` present: list variable names only.
- production migration requested without snapshot: block.
- unknown destructive command: block.
