# Server Deployment Rules For AI Agents

You are operating on a server protected by `opsctl`.

Read this file before deployment work. These rules apply to Codex, Claude Code, opencode, and any other AI tool working on this server.

## Mandatory Workflow

1. Read the server registry before planning deployment.
   If MCP is configured, call `read_server_context` first.
2. Do not assume a port, domain, Docker volume, container name, or Caddy route is free.
3. Confirm the local facts source is usable with MCP `install_check`, MCP resource `opsctl://install/check`, or CLI:

   ```bash
   opsctl install-check --json
   ```

4. Before production work, inspect the unified deploy gate with MCP `deploy_gates`, MCP resource `opsctl://deploy/gates`, or CLI:

   ```bash
   opsctl deploy-gates --json
   ```

5. Create a deploy plan before executing changes. If it updates a registered service, include `service_id`.
6. Run preflight before deployment:

   ```bash
   opsctl preflight ./deploy-plan.yml
   ```

7. If preflight reports `blocked`, stop and explain the issue.
8. If preflight reports `needs_approval`, request human approval. MCP `request_approval` only creates a request; it is not approval.
9. If the deployment affects production and the deploy gate is blocked or unclear, inspect `opsctl backup readiness`, `opsctl backup history`, `opsctl backup doctor`, and `opsctl backup plan <service-id> --dry-run`. Preflight blocks linked `before_deploy` services when backup dry-run or registered backup history is not ready.
10. If the deployment affects production and the deploy gate is blocked or unclear, inspect `opsctl snapshot-coverage --json` and ensure a snapshot exists before execution. Use `opsctl snapshot-inspect <snapshot-id> --json` to read a local snapshot manifest before rollback planning. Preflight blocks linked `before_deploy` services when registered snapshot coverage is not ready.
11. After deployment execution, read `opsctl deploy-journals --json` or MCP `list_deploy_journals` and inspect the latest journal before making additional changes.
12. Do not print raw secrets from `.env` files or command output.

## Forbidden Without Explicit Human Approval

- `rm -rf` against project roots, `/srv`, `/var/lib/docker`, data directories, backup paths, or Caddy configs.
- `docker compose down -v`
- `docker volume rm`
- `docker system prune`
- deleting or recreating production containers.
- overwriting `.env`, production compose files, Caddyfile, or systemd units.
- running production database migrations without a fresh snapshot.
- executing backups, repository prune, or restore commands outside an approved opsctl flow.
- exposing database or cache ports on `0.0.0.0`.
- reusing existing ports, domains, routes, container names, compose project names, or volumes.

## Secrets

You may list environment variable names. You must not reveal values.

Treat these as secrets:

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

## Safe Defaults

- Public traffic should enter through Caddy.
- App upstreams should prefer `127.0.0.1`.
- Databases and Redis should remain private by default.
- Docker Compose project names must be explicit.
- All production changes should leave an audit trail.

## If opsctl Is Missing

If `opsctl` is not installed yet, do not deploy production changes directly. Prepare the plan and ask the human operator how to proceed.

## MCP Tools

Allowed MCP tools are limited to reading context, inspecting deploy gates, backup dry-run readiness, registered backup history, snapshot coverage, analyzing projects, creating draft plans, preflight, approval requests, deploy execution approval requests, snapshot listing, snapshot inspect, and rollback dry-run.

Do not treat MCP as a shell, Docker control surface, or deployment execution surface.

If MCP resources are available, prefer these context resources before planning:

- `opsctl://server/context`
- `opsctl://install/check`
- `opsctl://registry/ports`
- `opsctl://registry/domains`
- `opsctl://backup/doctor`
- `opsctl://backup/readiness`
- `opsctl://backup/history`
- `opsctl://snapshot/coverage`
- `opsctl://deploy/gates`
- `opsctl://deploy/journals`
- `opsctl://safety/rules`

If MCP resource templates are available, use targeted lookups such as:

- `opsctl://registry/service/<service_id>`
- `opsctl://registry/port/<port>`
- `opsctl://registry/domain/<host>`
- `opsctl://snapshot/<snapshot_id>`
- `opsctl://backup/plan/<service_id>`
- `opsctl://deploy/journal/<journal_id>`
- `opsctl://schema/<name>`

If MCP prompts are available, use `safe_deploy_workflow` for deployment planning and `preflight_blocked_response` when preflight blocks a plan.

Use `opsctl://schemas` or `opsctl registry export-schema <name>` before creating registry YAML by hand.
