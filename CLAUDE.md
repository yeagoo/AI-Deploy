# Claude Code Project Instructions

Read and follow [`AGENTS.md`](./AGENTS.md) before planning or changing this repository. It is the canonical shared instruction set for architecture, safety, testing, documentation, Git, and deployment.

Claude Code-specific reminders:

- Read relevant repository documentation and the nearest subtree `AGENTS.md` before editing.
- Prefer small, reviewable changes and repository-native commands.
- Never bypass opsctl gates, approvals, evidence checks, path controls, or read-only MCP boundaries to complete a task.
- Never expose or commit `.env` values, local registry/state, production evidence, private imports, or generated output.
- Do not push, tag, release, deploy Cloudflare Pages, or mutate production infrastructure without explicit user authorization.

If this file and `AGENTS.md` appear to differ, follow the stricter safety constraint and update the canonical `AGENTS.md` rather than creating divergent policy here.
