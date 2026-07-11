# AI Contributor Guide

This file is the canonical repository-level instruction set for Codex, Claude Code, and other AI coding agents working on `opsctl`.

## Product contract

`opsctl` is a Rust deployment-safety controller for small production estates. It connects declarative server registry facts, read-only inspection, change planning, backup and restore evidence, explicit approvals, and tamper-evident audit records.

Preserve these invariants:

- Read-only inspection and dry-run planning are the default.
- A flag named `--execute` does not by itself grant broad authority. Each mutating command must retain its typed scope, approval, evidence, path, and policy checks.
- MCP is a read-only or request-producing surface. Do not add arbitrary shell execution, approval decisions, backup execution, deployment execution, restore execution, rollback execution, or resource deletion to MCP.
- High-risk operations stay fail-closed when identity, ownership, evidence, freshness, recovery, or approval is missing or ambiguous.
- Never weaken a gate merely to make a test, demo, or release pass.

Read `README.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, and `docs/QUALITY.md` before changing a safety boundary.

## Repository map

- `src/`: Rust CLI, TUI, MCP, registry, policy, backup/recovery, evidence, and deployment logic.
- `tests/`: CLI contracts and fixtures.
- `schemas/`: public registry and evidence schemas.
- `examples/server-registry/`: synthetic example registry, not production state.
- `packaging/`: Debian and systemd assets.
- `scripts/`: quality, packaging, release, upgrade, and opt-in E2E workflows.
- `templates/`: files installed or copied into managed server environments.
- `website/`: bilingual Fumadocs/Next.js documentation exported to Cloudflare Pages.

An `AGENTS.md` inside a subdirectory may add narrower rules for that subtree. The example and template `AGENTS.md` files describe managed-server behavior; they do not replace this repository-level guide.

## Safety and secrets

- Never print, commit, summarize, or copy credential values. Environment-variable names are safe; values are not.
- Do not read `.env` values unless the task explicitly requires credential use. When required, pass them privately to the process and report only sanitized classifications.
- Never commit local registry/state, runtime evidence, restore output, release archives, private imports, or generated build directories.
- Respect `.gitignore`. In particular, keep `.opsctl*`, `imports/`, `runtime/`, `release-evidence/`, `target/`, `website/.next/`, `website/out/`, `website/.wrangler/`, and environment files out of Git.
- Before publishing, inspect the staged file list and run a secret scan. Treat a public repository as permanent disclosure.
- Do not use real production service names, domains, paths, bucket names, snapshot IDs, approval tokens, or credential material in new examples or tests. Use `example.invalid`, `example.com`, temporary directories, and clearly synthetic IDs.
- Do not mutate `/etc`, `/srv`, `/var/lib/opsctl`, `/var/backups`, Docker, systemd, Caddy, an object store, or a production registry unless the user explicitly requested that external mutation.
- Production read-only gates use exact reviewed `sudo -n /usr/bin/opsctl --registry /srv/server-registry --state-dir /var/lib/opsctl ... --json` sudoers entries. They run as root only because readiness inspection needs protected project paths; never add arbitrary arguments or make private paths group-accessible instead.

## Rust implementation rules

- The crate uses Rust edition 2024 and forbids unsafe code.
- Prefer typed data and explicit state transitions over stringly typed shortcuts.
- Keep JSON output backward-compatible unless the task explicitly authorizes a schema change. JSON commands must emit one valid document to stdout; diagnostics belong on stderr and must be sanitized.
- Avoid `unwrap`, `expect`, `panic`, `todo`, debug prints, and hidden fallbacks in production paths. Propagate contextual errors with `anyhow` where appropriate.
- Bound file reads, subprocess timeouts, queue waits, collection sizes, and operator-controlled output.
- Preserve atomic/create-new writes, restrictive permissions, no-follow checks, path containment, global mutation locking, and audit logging on sensitive paths.
- Never convert a real failure, unavailable dependency, or skipped E2E prerequisite into a passing result.
- Add focused unit coverage and CLI contract coverage for behavior changes. Security fixes require a regression test for the failing boundary.

## Rust quality gates

Run the narrowest relevant tests while iterating, then use the full local gate for substantive Rust changes:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

For release, packaging, backup, restore, Docker, or systemd changes, read `docs/QUALITY.md` before running scripts. Many E2E and production rehearsal paths are intentionally opt-in. Do not enable `*_APPLY`, `*_EXECUTE`, sudo, Docker, cloud, or production-rehearsal modes without matching user authority.

Useful additional checks include:

```bash
bash -n scripts/*.sh
scripts/test-failure-matrix.sh
scripts/test-deb-install.sh
```

Do not run `scripts/release.sh` or a full release gate as a casual lint command; review its output and mutation contract first.

## Registry and operational fixtures

- Registry YAML is the declarative source of truth; SQLite is local state/index data, not a replacement registry.
- Update schemas, parsers, normalization, validation, examples, documentation, and contract tests together when registry fields change.
- Preserve unknown/ambiguous/missing/stale distinctions. Do not silently coerce them to safe or ready.
- `examples/server-registry/` must remain synthetic and internally consistent.
- Cleanup-request and evidence workflows may collect or write their narrowly defined evidence, but must not approve or delete resources unless a separately defined, explicitly authorized workflow permits it.

## Documentation platform

The documentation application is under `website/` and uses Bun, Next.js, Fumadocs, and static Orama search.

- Chinese and English are first-class. Every core MDX slug and navigation entry must exist in both `website/content/docs/zh/` and `website/content/docs/en/`.
- Do not mix fallback-language content into a published page. Update both languages in the same change.
- Keep examples secret-safe and production-neutral.
- Preserve static export compatibility for Cloudflare Pages. Server-only route handlers, middleware/proxy behavior, dynamic rendering, and Next.js image optimization require an explicit architecture decision.
- Keep `public/_redirects` for the default `/zh/` locale and `public/_headers` for the extensionless static search JSON content type.
- The stable Pages origin is `https://ai-deploy-7a3.pages.dev` unless a reviewed custom domain replaces it.

Use Node.js 22+ or Bun 1.3+ and run:

```bash
cd website
bun install --frozen-lockfile
bun run check
```

`bun run check` enforces bilingual content parity/secret patterns, ESLint, generated route types, TypeScript, and the static production build. For visual changes, also inspect at least one Chinese and one English page at desktop and mobile widths and check browser logs for hydration/runtime errors.

Cloudflare deployment is an external mutation. Preview first, deploy only when requested, and verify the stable domain, `/`, both locales, `/api/search`, `sitemap.xml`, and `robots.txt` after deployment.

## Git and release discipline

- Preserve unrelated user changes and local runtime state.
- Use focused commits and explain safety-boundary changes in the commit body or accompanying review.
- Before committing, run `git diff --check`, inspect `git status`, and verify ignored/generated files are not staged.
- Before pushing to a public remote, run an available secret scanner such as:

```bash
gitleaks git --staged --redact --no-banner .
```

- Pushing, tagging, creating releases, deploying Pages, and changing external project settings require explicit user authorization.
- Never manufacture release provenance. A release tag must reference the exact reviewed commit and use the requested signing policy.
- Do not reuse an already published version for different artifacts. Keep source version, package metadata, changelog, artifacts, signatures, and upgrade/rollback evidence aligned.

## Review priorities

Review in this order:

1. Secret exposure and unauthorized external mutation.
2. Safety-gate, approval, path-containment, locking, and audit correctness.
3. Backup/restore truthfulness and evidence integrity.
4. Data/schema compatibility and CLI JSON contracts.
5. Failure handling, resource bounds, and concurrency.
6. Test coverage, documentation parity, accessibility, and maintainability.

Report blockers honestly. Missing credentials, unavailable production state, or an unapproved mutation is not a reason to fabricate completion.
