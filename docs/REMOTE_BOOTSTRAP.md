# Typed Remote Bootstrap

`opsctl remote-bootstrap` upgrades only the `opsctl` Debian package on one explicit amd64 target. It is a CLI-only recovery bridge for a host whose installed opsctl predates self-upgrade support. It is not a generic SSH, SCP, package-management, or remote-shell interface.

## Private manifest

Create the manifest outside Git with mode `0600`. All file paths must be absolute, regular, non-symlink files owned by root or the current EUID; their immediate directories must not be group/world writable.

```yaml
schema_version: opsctl.remote-bootstrap-manifest.v1
target_id: example-host
host_ipv4: 192.0.2.10
ssh_port: 22
ssh_user: deploy
identity_file: /home/operator/.ssh/example
identity_sha256: 0000000000000000000000000000000000000000000000000000000000000000
known_hosts_file: /home/operator/.ssh/known_hosts_example
known_hosts_sha256: 0000000000000000000000000000000000000000000000000000000000000000
current_version: 0.6.8
prior_package_file: /srv/private/opsctl_0.6.8_amd64.deb
prior_package_sha256: 0000000000000000000000000000000000000000000000000000000000000000
new_package_file: /srv/private/opsctl_0.6.9_amd64.deb
new_package_sha256: 0000000000000000000000000000000000000000000000000000000000000000
```

Replace every synthetic hash with `sha256sum` output obtained through the operator's protected local workflow. Never paste private-key or environment-file contents into the manifest.

When the exact prior package exists only in an opsctl-created root backup directory, use a separate private recovery manifest:

```yaml
schema_version: opsctl.remote-prior-recovery-manifest.v1
target_id: example-host
host_ipv4: 192.0.2.10
ssh_port: 22
ssh_user: deploy
identity_file: /home/operator/.ssh/example
identity_sha256: 0000000000000000000000000000000000000000000000000000000000000000
known_hosts_file: /home/operator/.ssh/known_hosts_example
known_hosts_sha256: 0000000000000000000000000000000000000000000000000000000000000000
backup_id: 20260715T230100Z
expected_version: 0.6.8
expected_package_sha256: 0000000000000000000000000000000000000000000000000000000000000000
destination_file: /srv/private/opsctl_0.6.8_amd64.deb
```

The backup id is not a path: it must have exact `YYYYMMDDTHHMMSSZ` shape. Recovery reads only `/var/backups/opsctl-packages/<backup-id>/SHA256SUMS`, derives one safe matching package filename, and streams that package without creating a target-side copy:

```bash
opsctl remote-bootstrap recover-prior-plan /private/recovery.yml
opsctl remote-bootstrap recover-prior /private/recovery.yml \
  --evidence-sha256 <exact-plan-sha256> --execute
```

The destination must not exist. Any timeout, subprocess error, size overflow, hash mismatch, or metadata mismatch removes the newly created local file.

## Workflow

```bash
opsctl remote-bootstrap inspect /private/bootstrap.yml
opsctl remote-bootstrap plan /private/bootstrap.yml
opsctl remote-bootstrap request-execution /private/bootstrap.yml --reason "reviewed opsctl upgrade"
opsctl approve <approval-id>
opsctl remote-bootstrap execute /private/bootstrap.yml \
  --evidence-sha256 <exact-plan-sha256> \
  --approval-token <exact-token> \
  --execute
```

Approval must be performed by a different actor from the requester. Execution re-runs the complete plan and refuses changed target, SSH, artifact, package, sudo-policy, version, or install-check evidence.

The plan checks whether sudo authorizes every exact fixed command used for root-owned staging, hashing, `dpkg --install`, and cleanup. Missing authorization is a blocker; opsctl does not install a broad sudoers policy or fall back to a password.

## Recovery

Both exact packages are retained under private local state before transfer. Any failed install attempt triggers immediate restoration of the prior package and runs the fixed install check. A later operator-requested rollback is separate:

```bash
opsctl remote-bootstrap rollback /private/bootstrap.yml <journal-id> --dry-run
opsctl remote-bootstrap request-rollback /private/bootstrap.yml <journal-id> \
  --reason "reviewed rollback"
opsctl approve <rollback-approval-id>
opsctl remote-bootstrap rollback /private/bootstrap.yml <journal-id> \
  --execute --approval-token <exact-rollback-token>
```

Do not delete the retained local artifact directory until the target is stable and the rollback window is explicitly closed.

## Non-goals

- no password authentication;
- no DNS host targets or nonstandard SSH ports;
- no caller-provided remote command or remote path;
- no package other than `opsctl`, non-amd64 artifact, or downgrade;
- no MCP, privileged-helper, TUI, or packaged sudoers execution surface;
- no application, Caddy, firewall, DNS, database, Redis, object-store, or Zeabur mutation.
