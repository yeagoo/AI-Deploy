# Registry Schema

## Volume recovery profiles

`backups.yml` may contain `recovery_profiles`. Each profile matches one exact Docker volume name and declares `engine` (`postgres`, `mysql`, `mariadb`, `redis`, or `minio`), a version-tagged or digest-pinned `image`, optional safe relative `data_subpath`, bounded timeout/memory/CPU/PID/copy limits, environment variable names, and `recovery_probes`.

Probe kinds are `file_count`, `sha256`, `sql_readonly`, `redis_key_count`, and `minio_object_count`. SQL probes accept one `SELECT`, `SHOW`, or `EXPLAIN` statement and execute inside an explicit read-only transaction. Secrets remain in named environment variables and must not be stored in the registry. Duplicate exact-volume profiles, `latest` images, unsafe paths, arbitrary shell, and mutation-capable SQL are rejected.

The registry is a human-readable record of what exists on a single server. It is written as YAML and designed to be safe for AI tools to read.

Default path:

```text
/srv/server-registry/
```

Example path in this repository:

```text
examples/server-registry/
```

## Rules

### Separate Registered And Observed State

Registered state is what the operator says should exist.

Observed state is what `opsctl scan` sees at runtime.

They should not be silently merged. If they differ, `opsctl doctor` should report drift.

### No Raw Secrets

Registry files must not contain raw secrets.

Allowed:

```yaml
env_files:
  - path: /home/example/app/.env.prod
    redaction: keys_only
```

Not allowed:

```yaml
# Do not store database URLs, API keys, tokens, or passwords here.
# Reference env files with redaction instead.
```

### Stable IDs

IDs should be lowercase and stable.

Recommended pattern:

```text
service id: pcafev2
port id: pcafev2-postgres
domain id: pcafe-main
volume id: pcafe-pg-data
snapshot id: snap_YYYYMMDD_HHMMSS_name
approval id: appr_YYYYMMDD_HHMMSS_name
```

### Explicit Environment

Use one of:

```text
production
staging
development
external
unknown
```

Policies should be stricter for production.

## Files

### services.yml

Records deployed applications and their operational ownership.

Important fields:

- `id`
- `name`
- `root`
- `kind`
- `environment`
- `deploy_method`
- `status`
- `ports`
- `domains`
- `compose_projects`
- `containers`
- `volumes`
- `data_paths`
- `env_files`
- `deployment`
- `backup_policy`

`deployment` is an optional service-level contract. For an existing production service, deploy plans should stay inside this contract instead of inventing commands. It can declare allowed package-manager build scripts, migration commands, systemd unit actions, and managed static-site sync targets:

```yaml
deployment:
  build:
    - adapter: pnpm
      scripts:
        - build
        - start
  laravel:
    optimize: true
    config_cache: true
    route_cache: true
    view_cache: true
  migrations:
    - pnpm run db:migrate
  systemd:
    - unit: caddy.service
      actions:
        - reload
        - restart
  static_sites:
    - source: /home/example/app/dist
      destination: /srv/www/example
      deployment_id: example
```

### ports.yml

Records reserved ports and observed ports.

Reserved ports are intentional. Observed ports are scan results and should be refreshed.

Important fields:

- `port`
- `protocol`
- `bind`
- `service_id`
- `purpose`
- `exposure`
- `source`

### domains.yml

Records domain and Caddy routing intent.

Important fields:

- `host`
- `service_id`
- `upstream`
- `caddy_managed`
- `tls`
- `status`

### volumes.yml

Records Docker volumes and protected data paths.

Important fields:

- `name`
- `service_id`
- `kind`
- `mountpoint`
- `contains`
- `backup_policy`
- `protected`

### snapshots.yml

Records snapshot metadata and artifacts.

Important fields:

- `id`
- `plan_id`
- `created_at`
- `scope`
- `artifacts`
- `status`
- `limitations`

### backups.yml

Records backup repositories, per-service backup targets, and externally registered backup result history.

Important fields:

- `repositories`
- `provider`
- `repository`
- `repository_env`
- `password_env`
- `env`
- `retention`
- `targets`
- `service_id`
- `repository_id`
- `max_age_hours`
- `include_paths`
- `exclude_paths`
- `database_dumps`
- `schedule`
- `status`
- `history`
- `completed_at`
- `repository_snapshot_id`
- `repository_checks`
- `restore_drills`

`backups.yml` must store environment variable names only. It must not store Restic passwords, object storage keys, database passwords, or dump command strings with secrets.

External database dumps can either point at an already-created dump file, or declare a controlled package-manager script:

```yaml
database_dumps:
  - id: app-database-dump
    kind: external
    adapter: pnpm
    script: ops:backup-db
    working_dir: /srv/app
    verify_kind: postgres # or mysql / mariadb when that is the declared engine
    output_path: /var/lib/opsctl/backup-dumps/app/database.sql.zst
```

For scripted external dumps, `adapter` must be `npm`, `pnpm`, or `bun`, and `script` must also be declared in the matching service's `services.yml deployment.build` contract. `opsctl` runs only `<adapter> run <script>` without a shell, sets `OPSCTL_BACKUP_DUMP_OUTPUT` to a temporary local file path, then verifies that the script wrote a non-empty regular file before moving it to `output_path`. `verify_kind` is optional and tells restore drills which temporary database container to use for SQL import verification.

Database engines must be explicit. Registry writers must not infer MySQL/MariaDB/PostgreSQL from a project name, directory name, package manager, or framework. Mixed production servers should declare each dump independently with `kind: mysql`, `kind: mariadb`, `kind: postgres`, or `kind: external` plus `verify_kind`.

`history`, `repository_checks`, and `restore_drills` records are deployment facts written by controlled `opsctl backup` commands or entered by trusted backup automation. They do not contain secret values.

Production import promotion and production preflight treat a `before_deploy` service as blocked when the latest successful backup, latest successful repository check, or latest successful restore drill is missing, stale, failed, invalid, future-dated, or limited.

`max_age_hours` is optional on a backup target. When set, `opsctl backup history` treats the latest successful record for that target as stale if it is older than the policy.

### approvals

Each approval should be a separate file under:

```text
approvals/
```

Approvals must be specific. A generic "approve everything" record is not valid.

### deploy plans

Deploy plans live under:

```text
plans/
```

AI tools should create or propose deploy plans. `opsctl preflight` decides whether the plan is safe.

Important deploy plan fields:

- `id`
- `actor`
- `service_id` optional, but recommended when the plan changes an existing registered service
- `project_root`
- `intent`
- `environment`
- `changes`
- `snapshot_required`

For production mutating plans, `service_id` lets preflight connect the plan to registry backup policy. If the linked service has `backup_policy: before_deploy`, preflight checks `opsctl backup plan <service-id> --dry-run` internally and evaluates registered `opsctl backup history` freshness. It blocks when the backup dry-run or registered backup history is not ready.

Typed generated file writes live under `changes.files.typed`. They are intentionally not raw file content writes. The current supported kind is `caddy_route_snippet`:

```yaml
changes:
  files:
    typed:
      - path: /etc/caddy/conf.d/example.caddy
        kind: caddy_route_snippet
        params:
          host: example.com
          upstream: 127.0.0.1:3000
        mode: 416
```

The path must be absolute and safe. Existing files are overwritten only when they already contain the opsctl typed-file marker. Use `opsctl caddy-routes --json` to inspect managed and unmanaged Caddyfile route blocks before proposing route changes.

### policies.yml

Records default safety settings, protected paths, blocked command patterns, dangerous operation names, and redaction patterns. `opsctl registry validate` checks this file against the embedded `policies` schema; the Rust policy engine still owns the executable enforcement logic.

## Schema Files

Initial schema drafts live in:

```text
schemas/
```

They are YAML-formatted JSON Schema drafts. They are intentionally strict about IDs and required fields, but still simple enough to evolve.

## Drift

Examples of drift:

- a port is registered as free but `ss` shows it is listening
- Caddy routes a domain to a different upstream than the registry says
- a Docker volume exists but no registered service owns it
- a registered production service has no recent snapshot
- a compose project uses a hard-coded `container_name` not in the registry

Drift is not always an error, but it must be visible before deployment.
