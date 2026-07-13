# Managed Projects and Git Delivery

`opsctl project` turns bounded project evidence into a reviewed project contract and the existing typed `DeployPlan`. It does not introduce arbitrary shell execution or a second deployment executor.

## Runtime Profiles

```bash
opsctl project profiles --json
```

The initial managed profiles are:

- `docker_compose`: pins the one analyzed Compose file, then performs an optional typed build followed by Compose up; named volumes require an existing backup and restore contract.
- `static_site`: an allowlisted package-manager build followed by bounded, no-delete static sync under a reviewed static root.
- `node_systemd`: package-manager build, managed systemd unit, daemon reload, enable, restart, and health checks.
- `laravel_systemd` (assisted): detects typed Laravel cache actions, but remains blocked until a reviewed PHP-FPM or process runtime contract exists; it never substitutes the development server for production.

Unsupported or ambiguous projects return `assisted` or `unsupported`. They never fall back to `sh -c`, arbitrary Docker commands, or guessed data ownership.

## Compile a Project

```bash
opsctl project compile /srv/projects/example \
  --service-id example \
  --runtime-user deploy \
  --env-file /etc/opsctl/services/example.env \
  --domain example.com \
  --tls automatic \
  --json
```

The report contains analyzer evidence, the selected profile, required input names, a secret-free managed contract, and a typed deploy plan when status is `ready`. When no runtime port is declared, Node profiles receive a stable port in `20000-29999` that does not collide with the Registry. Explicit `--port` values are never silently changed.

`--tls automatic` is the production default. It requires a public DNS hostname and produces a managed Caddy route. `--tls none` is intended for non-production HTTP-only targets and is blocked for production. Static profiles compile to an allowlisted Caddy `file_server` root; service profiles compile to a localhost reverse proxy. Certificate issuance remains a Caddy runtime result and is not claimed by compilation.

Environment files contribute key names only; values are never returned or hashed into plans. A managed environment file must be an absolute path outside the source repository, must not be a symlink, and must deny group/other access. Assignments must be valid, unique, and non-empty. Every preflight and deploy revalidates the file and required key set, so post-queue permission or key drift fails closed.

Database evidence is inferred only from Compose image names, dependency names, and environment key names. Declared `db:migrate` or `migrate` scripts compile to a typed package-manager migration step. Production database plans remain `assisted` until the registered service has current backup, repository-check, and restore-drill readiness. Migrations run after snapshot/approval gates and before service restart, as the managed non-root owner, without a shell.

First production onboarding embeds a deployment contract in the plan. Preflight requires human approval before creating the new Registry service. A plan cannot use an embedded contract to override an existing Registry contract.

## Queue an Immutable Git Delivery

Git delivery requires the project path to be the repository root, a clean worktree, an exact full commit object id, an exact branch, a configured origin, and a matching local `origin/<branch>` reference. Tracked symbolic links and Git submodules are rejected because their external content is not fully bound by the parent commit. The origin URL is represented only by a SHA-256 fingerprint.

```bash
opsctl project git-trigger /srv/projects/example \
  --service-id example \
  --runtime-user deploy \
  --env-file /etc/opsctl/services/example.env \
  --port 3000 \
  --commit <full-commit-id> \
  --branch main \
  --json
```

The command is read-only by default. `--execute` writes a create-new queue directory under `STATE/git-deliveries/<trigger-id>/` containing:

- `trigger.json`
- `project-contract.yml`
- `deploy-plan.yml`

Repeating the same trigger is idempotent only when all stored hashes and Git identities still match. Tampered or colliding records fail closed.

Queueing does not deploy. Continue through the existing boundaries:

```bash
opsctl preflight <queued-plan> --json
opsctl snapshot <queued-plan> --dry-run
opsctl deploy <queued-plan> --dry-run --snapshot <snapshot-id> --json
```

Production execution still requires current Registry policy, backup and restore evidence, snapshot verification, approvals, the global mutation lock, and typed deploy execution.

The queued plan embeds the immutable Git identity. Every later preflight and deploy rechecks the worktree, HEAD, branch, origin fingerprint, and `origin/<branch>` reference. A post-queue source change blocks execution.

## Authorized Push-to-Production Delivery

Automatic delivery is a reviewed capability, not an approval bypass. First review the current project class and create a constrained authorization request:

```bash
opsctl project authorize-delivery /srv/projects/example \
  --service-id example \
  --runtime-user deploy \
  --env-file /etc/opsctl/services/example.env \
  --port 3000 \
  --commit <full-commit-id> \
  --branch main \
  --reason "allow bounded production delivery from main" \
  --expires-at 2026-08-01T00:00:00Z \
  --json

# An independent operator reviews the bound constraints and scopes.
opsctl approve <approval-id> --json
```

The authorization binds the canonical project root, service and plan id, origin fingerprint, branch, production environment, runtime Profile, and `stateless|database` class. Its scopes must include every current preflight scope plus `automatic_delivery` and `deploy_execution`. A later Profile, origin, branch, path, environment, statefulness class, or newly required scope change blocks reuse even when the approval has not expired.

After approval, a trusted Git hook or CI runner updates the checked-out worktree and its local `origin/main` ref to the pushed commit, then invokes:

```bash
opsctl project deliver /srv/projects/example \
  --service-id example \
  --runtime-user deploy \
  --env-file /etc/opsctl/services/example.env \
  --port 3000 \
  --commit <full-pushed-commit-id> \
  --branch main \
  --execute \
  --json
```

The installed `templates/opsctl-git-push-deliver.sh` is a narrow bridge for that final call. It accepts only a canonical lowercase full commit and the configured branch, constructs argv without a shell, and never performs checkout, fetch, approval, or secret lookup. Configure its `OPSCTL_DELIVERY_*` variables in the trusted runner environment. Set `OPSCTL_DELIVERY_MODE=dry-run` while qualifying a project and change it to `execute` only after the exact authorization and production gates have been reviewed. The runner must update the worktree safely before invocation; opsctl then independently verifies clean HEAD, branch, origin fingerprint, and `origin/<branch>`.

The packaged `PRODUCTION_DELIVERY_HANDOFF.md` contains the complete operator handoff and Go/No-Go checklist. Do not make the bridge a broad passwordless sudo command and do not source application Secret files as bridge configuration.

Execution performs immutable queueing, a complete local snapshot, checksum verification, fresh preflight, snapshot-bound typed deployment, health checks, Registry write-back, audit logging, and a create-new terminal delivery result. Repeating the same successful commit returns `already_completed`; tampered queue/result records or failed/partial attempts are not treated as success.

Stateless automation requires no database evidence, migration, Compose named volume, or ambiguous persistent state. Common database automation is limited to managed Node services with PostgreSQL, MySQL/MariaDB, or SQLite evidence, an allowlisted `db:migrate|migrate` script, and current registered backup, repository-check, restore-drill, and snapshot readiness. Missing or stale recovery evidence, unknown engines, stateful Compose, or database evidence without a typed migration returns `manual_required`.

## Supply-chain and build containment

Managed Node plans bind the exact dependency lockfile SHA-256 and run `npm ci`, `pnpm install --frozen-lockfile`, or `bun install --frozen-lockfile` with lifecycle scripts disabled before the allowlisted build. The install and build run as the managed non-root owner with a clean environment containing only the required managed keys. The source and lockfile are revalidated at every preflight and deploy.

Compose plans bind the Compose file and every detected Dockerfile. Every external Compose image and every non-`scratch` Dockerfile `FROM` must use an `@sha256:<digest>` reference. Mutable tags, dynamic base-image arguments, privileged containers, host networking, Docker socket mounts, and root bind mounts keep the project `assisted`. Compose commands receive the same clean-environment treatment. This is bounded build containment, not a claim of a separate VM or network-disconnected builder; package downloads and Docker builds still use operator-configured repositories and network policy.

## Health gate and controlled rollback

Production managed plans enable the existing typed post-deploy health gate with a bounded stabilization window and one rollback attempt. A failed health journal is evaluated read-only first:

```bash
opsctl deploy-health-controller ./deploy-plan.yml --journal <journal-id> --dry-run --json
opsctl request-health-rollback ./deploy-plan.yml --journal <journal-id> --reason "health gate failed"
# after independent approval
opsctl deploy-health-controller ./deploy-plan.yml --journal <journal-id> --execute --approval-token <token> --json
```

The token binds the exact plan digest, failed journal, and snapshot. Execution also requires a journal-specific approved `health_rollback.<journal-id>` scope and uses create-new claim/result records, so it cannot loop or silently reuse another approval. Automatic scope is limited to Caddy configuration when it was both changed and captured. Registry write-back, application code/images, static output, systemd units, migrations, and data return `manual_required`; opsctl does not pretend the snapshot can restore artifacts it did not capture or overwrite unrelated Registry changes. MCP remains read-only and exposes no controller execution path.
