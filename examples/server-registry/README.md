# Example Server Registry

This directory is a sample registry for `opsctl`.

It is not a live inventory. It shows the intended shape of a single-server registry that AI tools can read safely.

Files:

```text
AGENTS.md       rules AI tools must follow on this server
policies.yml    local safety policy settings
services.yml    registered applications
ports.yml       reserved and observed ports
domains.yml     Caddy/domain routing intent
volumes.yml     Docker volumes and protected data paths
snapshots.yml   snapshot records
backups.yml     backup repositories and Restic dry-run targets
plans/          proposed deploy plans
approvals/      approval records
history/        audit/export artifacts
```

Secrets must not be stored in this directory. Environment files can be referenced by path with `keys_only` redaction.
