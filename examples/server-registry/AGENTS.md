# Server Rules For AI Tools

This server uses `opsctl` as a deployment safety gate.

Before deploying, read:

- `services.yml`
- `ports.yml`
- `domains.yml`
- `volumes.yml`
- `backups.yml`
- `policies.yml`

## Required Deployment Workflow

1. Analyze the target project.
   If MCP is configured, call `read_server_context` first.
2. Confirm the local facts source is usable with MCP `install_check`, MCP resource `opsctl://install/check`, or CLI:

   ```bash
   opsctl install-check --json
   ```

3. Before production work, inspect the unified deploy gate with MCP `deploy_gates`, MCP resource `opsctl://deploy/gates`, or CLI:

   ```bash
   opsctl deploy-gates --json
   ```

4. Create a deploy plan under `plans/`. If it changes a registered service, set `service_id`.
5. Run:

   ```bash
   opsctl preflight plans/<plan>.yml
   ```

6. If preflight is blocked, stop.
7. If approval is required, ask the human operator. MCP `request_approval` creates only a request.
8. If the plan affects production and the deploy gate is blocked or unclear, inspect `opsctl backup readiness`, `opsctl backup history`, `opsctl backup doctor`, and `opsctl backup plan <service-id> --dry-run`. Preflight blocks linked `before_deploy` services when backup dry-run or registered backup history is not ready. If backup history reports stale targets, future records, invalid timestamps, or missing successful targets, stop and ask for a human-confirmed backup.
9. If the plan affects production and the deploy gate is blocked or unclear, inspect `opsctl snapshot-coverage --json` and create or verify a snapshot first. Use `opsctl snapshot-inspect <snapshot-id> --json` to read a local snapshot manifest before rollback planning. Preflight blocks linked `before_deploy` services when registered snapshot coverage is not ready.
10. After deployment execution, read `opsctl deploy-journals --json` or MCP `list_deploy_journals` and inspect the latest journal before making additional changes.

## Never Do These Directly

- delete project roots, data paths, backup paths, Docker volumes, or Caddy configs.
- run `docker compose down -v`.
- run `docker volume rm`.
- run `docker system prune`.
- overwrite `.env` files.
- expose database or cache ports publicly.
- reuse ports, domains, routes, container names, compose project names, or volumes.

## Secret Handling

You may list env variable names. You must not print values.

## MCP Boundary

MCP may read facts, inspect deploy gates, inspect backup dry-run readiness, inspect registered backup history, inspect registered snapshot coverage, run preflight, request approval, request deploy execution approval, list and inspect snapshots, and produce rollback dry-runs. It must not be used for arbitrary shell, Docker deletion, Caddy overwrite, approval decisions, direct deploy execution, backup execution, or rollback execution.

Preferred MCP resources:

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

Preferred MCP resource templates:

- `opsctl://registry/service/<service_id>`
- `opsctl://registry/port/<port>`
- `opsctl://registry/domain/<host>`
- `opsctl://snapshot/<snapshot_id>`
- `opsctl://backup/plan/<service_id>`
- `opsctl://deploy/journal/<journal_id>`
- `opsctl://schema/<name>`

Use `safe_deploy_workflow` when a client supports MCP prompts.

Read `opsctl://schemas` or run `opsctl registry export-schema <name>` before editing registry YAML manually.
