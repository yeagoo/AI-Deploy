# Debian Install And Packaging Notes

Target platform: Debian 13 on a single server.

## Build

Install the Rust toolchain, then build:

```bash
cargo build --release
```

The release binary will be:

```text
target/release/opsctl
```

## Install

From the repository root:

```bash
sudo scripts/install-debian.sh ./target/release/opsctl
```

The installer creates:

```text
/usr/local/bin/opsctl
/srv/server-registry
/var/lib/opsctl
```

It also creates an `opsctl` system user/group when the platform provides `adduser`/`addgroup` or `useradd`/`groupadd`. The registry directory, top-level registry files, and standard registry subdirectories are grouped to `opsctl`; the private state root and its control-plane entries are owned by `opsctl:opsctl`. Package installation and upgrades run the layout check as that service identity so root-owned audit files are not introduced during installation. Upgrades do not recursively change restored UID/GID metadata or root-created database dump ownership.

If `/srv/server-registry/services.yml` does not exist, the installer copies the example registry as a starting template.

The installer runs a read-only layout check before returning:

```bash
sudo -u opsctl opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl install-check
```

## Build A Debian Package

From the repository root:

```bash
scripts/build-deb.sh
```

The package is written under:

```text
target/debian/
```

The package installs:

```text
/usr/bin/opsctl
/usr/share/doc/opsctl/
/usr/share/opsctl/examples-server-registry/
/usr/share/opsctl/schemas/
/usr/share/opsctl/templates/
/usr/share/opsctl/scripts/install-sudoers.sh
/usr/share/opsctl/scripts/production-onboarding-check.sh
/usr/lib/systemd/system/opsctl-install-check.service
/usr/lib/systemd/system/opsctl-install-check.timer
/usr/lib/systemd/system/opsctl-backup-run@.service
/usr/lib/systemd/system/opsctl-backup-run@.timer
/usr/lib/systemd/system/opsctl-backup-check@.service
/usr/lib/systemd/system/opsctl-backup-check@.timer
/usr/lib/systemd/system/opsctl-restore-drill@.service
/usr/lib/systemd/system/opsctl-restore-drill@.timer
```

The package `postinst` creates the `opsctl` user/group, `/srv/server-registry`, `/var/lib/opsctl`, `/var/lib/opsctl/deploy-journals`, `/var/lib/opsctl/restore-drills`, and `/etc/opsctl` if needed. It copies the example registry only when `/srv/server-registry/services.yml` does not already exist. Timer units are installed as files only; they are not enabled automatically.

Backup credentials belong in an operator-managed environment file such as `/etc/opsctl/backup.env`, not in the registry:

```sh
RESTIC_REPOSITORY=s3:s3.example.invalid/bucket/path
RESTIC_PASSWORD=...
AWS_ACCESS_KEY_ID=...
AWS_SECRET_ACCESS_KEY=...
```

Enable timers explicitly per service or repository after `opsctl backup plan`, `opsctl backup check`, and `opsctl backup drill` have been reviewed:

```bash
opsctl backup timer plan --service-id pcafev2
opsctl backup timer install --service-id pcafev2
opsctl backup timer install --service-id pcafev2 --execute
opsctl backup timer status --service-id pcafev2
```

The 0.6.1-and-later timer templates deterministically spread each instance across a 23-hour window instead of launching every service in one short cluster. Reviewed scheduled mutations opt into a bounded global-lock queue with `OPSCTL_LOCK_WAIT_SECONDS`; interactive commands remain fail-fast unless an operator explicitly sets that environment variable. The binary rejects waits longer than six hours, and each unit also has a finite systemd start timeout. Do not enable production timers until a read-only repository probe, a generated-object storage smoke test, and `opsctl backup check <repository-id>` all succeed with the intended credential.

Opsctl 0.6.4-and-later executed Restic backups first run plain `restic unlock` to remove only provider-classified stale locks left by interrupted commands. The plan never adds `--remove-all`, does not force-remove active locks, and stops before database dumps or repository writes if stale-lock recovery fails. This step is Restic-specific and is not added to rustic plans.

`opsctl-restore-drill@.service` uses `backup drill --scheduled`, which is restricted to `/var/lib/opsctl/restore-drills/<service>` and creates a unique `run-*` staging child for each execution. Operators should prune old staging drill directories after reviewing history and storage use.

Old scheduled drill staging directories can be reviewed and pruned with:

```bash
opsctl backup drill-cleanup --keep-days 14 --keep-count 5
opsctl backup drill-cleanup --keep-days 14 --keep-count 5 --execute
```

The cleanup command is scoped to `/var/lib/opsctl/restore-drills`, only considers immediate service `run-*` directories, and refuses symlink/non-directory cleanup targets.

For a production onboarding readiness pass that does not run backup jobs and does not promote an import:

```bash
/usr/share/opsctl/scripts/production-onboarding-check.sh /path/to/generated-import
```

This wraps:

```bash
opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl backup onboarding-check --import-dir /path/to/generated-import
```

It reports the required `backup run`, `backup check`, `backup drill`, `registry import-check --scan-observed`, and `registry promote-import --dry-run --scan-observed` steps.

Create the Restic credential file from the packaged template and restrict it to root/opsctl before running apply mode:

```bash
sudo install -d -m 0750 -o root -g opsctl /etc/opsctl
sudo install -m 0600 -o root -g opsctl /usr/share/opsctl/templates/restic.env.example /etc/opsctl/restic.env
sudo editor /etc/opsctl/restic.env
```

The real file must define `RESTIC_REPOSITORY`, `RESTIC_PASSWORD`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY`. Keep it out of the registry and out of chat transcripts.

After reviewing the planned commands and real backup credentials, the same script can execute the backup/check/drill portion of the flow:

```bash
OPSCTL_ONBOARDING_APPLY=1 \
OPSCTL_BACKUP_ENV_FILE=/etc/opsctl/restic.env \
OPSCTL_ONBOARDING_REPO_INIT=1 \
OPSCTL_ONBOARDING_SERVICES="caddy mf8 open-launch rankfan-new screenhello mariadb-edu-rich toolso-ai-open pcafev2" \
OPSCTL_ONBOARDING_REPOSITORIES="restic-r2-main" \
/usr/share/opsctl/scripts/production-onboarding-check.sh /path/to/generated-import
```

Apply mode requires explicit service and repository ids. If `OPSCTL_ONBOARDING_REPO_INIT=1` is set, it first reviews and executes `opsctl backup repo-init` with the deterministic `repo-init:<repository>` approval token; use that only for a new repository. It then runs only typed `opsctl backup run`, `opsctl backup check`, and batch `opsctl backup drill-suite --execute` commands. `OPSCTL_RESTORE_DB_IMPORT_CHECK` defaults to `1` for the drill-suite step unless already set. Finally it runs `registry import-check --scan-observed` and `registry promote-import --dry-run --scan-observed`. It still does not automatically promote the import or write the active registry through promotion.

## Package Install-Level Test

The install-level package smoke is opt-in and uses a clean Debian container:

```bash
scripts/test-deb-install.sh
```

By default it prints the planned image and package path without starting Docker. To run it:

```bash
export OPSCTL_DEB_TEST_APPLY=1
scripts/test-deb-install.sh
```

The test runs `dpkg -i`, validates the `opsctl` user/group, registry/state permissions, systemd unit files, sudoers template syntax, an idempotent reinstall/upgrade path, and `dpkg -r`. Set `OPSCTL_PREVIOUS_DEB=/path/to/old.deb` to test an actual upgrade from an older package.

## Release Artifacts

The local release script runs quality gates, builds target binaries, builds Debian packages for supported Linux targets, writes checksums, creates `RELEASE_MANIFEST.json`, and creates release notes:

```bash
scripts/release.sh
```

Useful overrides:

```bash
OPSCTL_RELEASE_TARGETS="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu" scripts/release.sh
OPSCTL_RELEASE_SKIP_QUALITY=1 scripts/release.sh
```

Artifacts are written under `target/release-dist/v<version>/`.

Verify a generated release directory with:

```bash
scripts/release-verify.sh target/release-dist/v<version>
```

## Sudoers Helper Policy

The package ships a template and an installer for the minimal helper allowlist. Dry-run the generated policy first:

```bash
OPSCTL_AI_USER=ai-deploy scripts/install-sudoers.sh
```

Install only after review:

```bash
sudo OPSCTL_AI_USER=ai-deploy OPSCTL_SUDOERS_APPLY=1 scripts/install-sudoers.sh
opsctl helper sudoers-check --path /etc/sudoers.d/opsctl-helper
```

The sudoers policy allows the typed root helper plus three exact root read-only gates. Root is required because deploy readiness inspects protected registered production paths; the alias fixes the binary, Registry/State paths, subcommand, and `--json` so the operator cannot append arbitrary opsctl arguments. It must never grant Docker, shell, `rm`, `systemctl`, arbitrary opsctl commands, or general `NOPASSWD: ALL`.

## Runtime Environment

Recommended environment variables:

```bash
export OPSCTL_REGISTRY=/srv/server-registry
export OPSCTL_STATE_DIR=/var/lib/opsctl
export OPSCTL_ACTOR=codex
```

Equivalent explicit command:

```bash
opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl status
```

The production state directory is deliberately mode `0700`; membership in the `opsctl` group does not grant direct access. Operators should use the reviewed sudoers policy for the three production gates:

```bash
sudo -n /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl install-check --json
sudo -n /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl registry validate --json
sudo -n /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl deploy-gates --json
```

Do not make `/var/lib/opsctl` or protected project paths group-readable/group-writable to avoid the exact root read-only boundary.

## Smoke Test

After install:

```bash
opsctl status
opsctl install-check
opsctl doctor
opsctl tui --dump
opsctl mcp < /dev/null
```

`opsctl mcp < /dev/null` should exit successfully without printing normal CLI output.

## Optional DigitalOcean E2E Smoke

The true VPS smoke harness is opt-in. By default it prints the planned settings and exits without creating a droplet:

```bash
scripts/e2e-digitalocean.sh
```

To create a temporary Debian droplet and run the full install + Docker Compose + Caddy deploy smoke:

```bash
export OPSCTL_E2E_APPLY=1
scripts/e2e-digitalocean.sh
```

The script reads `DOKEY`, `dokey`, or `DIGITALOCEAN_TOKEN`. It also reads `~/.env` if present. The default region is `sfo3`; override with `DO_REGION` if needed. The droplet is destroyed after the smoke test unless `OPSCTL_E2E_DESTROY=0` is set. Set `DO_SSH_KEY_IDS` to use an existing DigitalOcean SSH key; if it is not set, the script reuses a matching local public key already registered in DigitalOcean or creates a temporary key from `DO_SSH_PUBLIC_KEY_PATH`, `~/.ssh/id_ed25519.pub`, or `~/.ssh/id_rsa.pub`. Temporary keys are deleted when the droplet is destroyed.

The VPS smoke uses a `.deb` package path by default:

```bash
OPSCTL_E2E_DEB=1 OPSCTL_E2E_APPLY=1 scripts/e2e-digitalocean.sh
```

That path builds a package, uploads it, runs `dpkg -i`, checks user/group ownership, validates systemd unit files and the sudoers template, reinstalls the same package as an idempotent upgrade check, runs install-check, and then runs the Docker/Caddy deploy smoke. If `OPSCTL_PREVIOUS_DEB=/path/to/old.deb` is set, the script installs that package first and upgrades to the newly built package.

The `.deb` architecture must match the DigitalOcean image. `debian-13-x64` requires an `amd64` package. If the local build host is another architecture, set `OPSCTL_E2E_DEB_PATH=/path/to/opsctl_<version>_amd64.deb`, set `OPSCTL_E2E_BUILD_TOOL=cross` with a working Docker daemon, or set `OPSCTL_E2E_REMOTE_BUILD=1` to upload the source tree and build the matching package on the temporary droplet before installation. The remote build path installs a minimal rustup stable toolchain instead of Debian's `rustc` package, because Debian 13's packaged compiler may lag current crate MSRV requirements.

The full Debian 13 amd64 VPS regression command used for the current phase is:

```bash
OPSCTL_E2E_APPLY=1 \
OPSCTL_E2E_DEB=1 \
OPSCTL_E2E_FULL=1 \
OPSCTL_E2E_REMOTE_BUILD=1 \
OPSCTL_E2E_HELPER_SMOKE=1 \
OPSCTL_E2E_BACKUP_DRILL=1 \
DO_SIZE=s-2vcpu-2gb \
scripts/e2e-digitalocean.sh
```

In `.deb` mode, `OPSCTL_E2E_HELPER_SMOKE=1` installs the minimal sudoers helper policy for a temporary `opsctl-ai-e2e` user, validates it with `opsctl helper sudoers-check`, approves a no-op helper deploy plan, and runs `opsctl helper run-deploy-operation` through `sudo -n` as the non-root user.

With `OPSCTL_E2E_BACKUP_DRILL=1`, the full smoke also initializes a real local Restic repository, records a backup snapshot, runs `opsctl backup check` so `repository_checks` is appended to `backups.yml`, runs `backup restore-plan`, executes an approval-token-gated restore into a staging directory, verifies file/hash/SQL restore output with isolated no-network database import checking, records `restore_drills`, and verifies production `preflight` passes only after the backup history, repository check, restore drill, and snapshot coverage gates are ready.

The full smoke is enabled by default after droplet creation. Set `OPSCTL_E2E_FULL=0` to run only install/read-only checks. When `.deb` mode and droplet destruction are enabled, the script also runs `dpkg -r opsctl` at the end and verifies that registry/state directories remain. Override with `OPSCTL_E2E_REMOVE=0` if you retain the droplet for debugging.

It should not start a public service by default. MCP should remain a local stdio process launched by the AI client or a restricted user session.

## Optional Volume Protection Campaign Timer

The package installs but does not enable `opsctl-volume-protect-campaign@.service` and `.timer`. First review and start a campaign manually, then optionally enable bounded resume for its recorded id:

```bash
opsctl backup volume-protect campaign-status --campaign-id <campaign-id> --json
systemctl enable --now opsctl-volume-protect-campaign@<campaign-id>.timer
```

The timer only resumes the recorded campaign configuration. It cannot create a campaign, approve cleanup, reconcile evidence, or delete a Docker volume.

Evidence signing keys are created only by an explicit CLI `evidence-keygen --execute` under the configured state directory, or supplied to a signing operation as a restrictive systemd credential file. Trust registration, expiry, revocation, and audit checkpoints also require explicit CLI operations. Back up private keys through an operator-controlled secret process and evidence bundles through independently enforced retention/Object Lock; the Debian package never generates, rotates, trusts, exports, or enables a signing key automatically. Isolated database and application verification require exact version-pinned images to be preloaded because opsctl uses Docker `--pull never`.
The service follows the existing backup units and runs with system service privileges because Docker volume mountpoints are normally unreadable to the unprivileged `opsctl` account; its command remains constrained by the campaign journal, safety fuses, and global opsctl lock.
Disable the timer after the campaign reports `completed`; completed resumes are safe no-ops but continuing to schedule them is unnecessary.

## Upgrade Notes

Before replacing the binary:

```bash
opsctl status --json
opsctl snapshots --json
cp -a /srv/server-registry /srv/server-registry.before-opsctl-upgrade
```

After replacing the binary:

```bash
opsctl doctor
opsctl tui --dump
```
