# Production Delivery Handoff

This checklist turns the supported managed-delivery implementation into an operated production path. It does not broaden the supported project classes or authorize a production mutation by itself.

## 1. Release candidate

The reviewed candidate must have one coherent version across `Cargo.toml`, `Cargo.lock`, Debian metadata, the binary, release manifests, checksums, signatures, and the eventual Git tag.

Before installation:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
scripts/test-managed-delivery-templates.sh
scripts/test-failure-matrix.sh
cargo audit
cargo deny check
scripts/build-deb.sh
```

Do not tag, publish, or install an artifact built from an unreviewed or dirty tree. The release script refuses tracked, staged, or untracked source changes and records the exact full source commit in the release manifest. Preserve the previous Debian package and the existing Registry/State backup for rollback.

## 2. Server identity and paths

Run opsctl through the reviewed operations identity. Confirm that it can read the production Registry and own the State directory without making project Secret files broadly readable.

Expected defaults:

```text
binary:       /usr/bin/opsctl
registry:     /srv/server-registry
state:        /var/lib/opsctl
project root: /srv/projects/<service>
service env:  /etc/opsctl/services/<service>.env
```

The project root and service env file must be regular, non-symlink paths with the ownership and permissions required by the managed compiler. The service env file contains application values; the delivery configuration contains only paths and non-secret identifiers.

## 3. Trusted Git runner

GitHub, a receive hook, or a self-hosted runner authenticates the push and updates the reviewed worktree. That runner must:

1. accept only the configured repository and branch;
2. fetch the exact pushed commit without accepting an abbreviated id;
3. update the configured worktree without rewriting a dirty tree;
4. leave `HEAD`, the checked-out branch, and `origin/<branch>` on the same commit;
5. invoke the bridge with the exact lowercase full commit and branch;
6. serialize updates for one production service.

Opsctl deliberately does not fetch, checkout, merge, reset, or expose a public webhook. Do not compensate with a broad root SSH command or unrestricted passwordless sudo.

Install a project-specific copy of the non-secret example configuration and the bridge from `/usr/share/opsctl/templates/`. Keep the bridge configuration readable only by the trusted runner and operations group. Keep application Secret values in the separate service env file.

## 4. Qualification before execution

Start with:

```text
OPSCTL_DELIVERY_MODE=dry-run
```

Invoke the bridge with the current full commit and branch. A Go result requires the project to classify as `stateless` or `database`, with no blocker or missing required approval scope.

For database delivery, verify all of the following are current for the exact registered service:

- successful backup snapshot;
- successful repository check;
- successful isolated restore drill;
- complete local deployment snapshot coverage;
- typed `db:migrate` or `migrate` adapter;
- supported PostgreSQL, MySQL/MariaDB, or SQLite evidence.

Stateful Compose, unknown database engines, missing migration adapters, ambiguous persistence, and stale recovery evidence remain `manual_required`.

## 5. Independent authorization

Create the constrained authorization request with `project authorize-delivery`. A different operator reviews and approves it. Confirm the approval binds the exact service, canonical project root, origin fingerprint, branch, production environment, runtime Profile, delivery class, plan id, required scopes, and expiry.

Do not reuse an ordinary deployment approval. Do not approve a request created by the same identity. Prefer the shortest practical expiry; the controller rejects an automatic-delivery authorization longer than 30 days.

## 6. First production delivery

Change only the reviewed project configuration to:

```text
OPSCTL_DELIVERY_MODE=execute
```

Run the first delivery in a maintenance window with an operator watching the service, Caddy, systemd, backup repository, opsctl audit, and deploy journal. Verify the terminal delivery result and external application behavior. Repeating the same successful commit must return `already_completed`.

If the attempt creates a claim but no terminal result, stop. The controller intentionally requires manual review and will not automatically replay a possibly partial mutation.

## 7. Rollback and No-Go conditions

Keep the previous package, Registry/State backup, deployment snapshot, prior application artifact, and database recovery procedure available throughout the first rollout.

Automatic health rollback is currently limited to an exact captured Caddy configuration change. Application code, images, static output, systemd units, migrations, Registry write-back, and data recovery can return `manual_required`. A project is No-Go for unattended delivery when its required failure recovery depends on an automatic scope opsctl does not currently provide.

Other No-Go conditions include:

- dirty or mismatched Git worktree/ref;
- missing independent authorization;
- changed authorization constraints or scopes;
- stale/missing backup, check, drill, or snapshot evidence;
- missing Secret keys or unsafe env-file permissions;
- domain/port/ownership conflict;
- unsupported build/runtime Profile;
- failed or partial prior delivery without operator reconciliation;
- inability to restore the previous package and Registry/State.

## 8. External actions still required

An operator must configure GitHub environment protection, SSH or self-hosted runner authentication, branch protection, the safe project-specific worktree update, service env values, DNS, production authorization approval, release signing/tagging, package installation, and the observed first-production Go/No-Go decision. None of those external facts are manufactured by source tests.
