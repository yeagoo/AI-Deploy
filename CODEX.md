# Codex Project Instructions

Read and follow [`AGENTS.md`](./AGENTS.md) as the canonical project instruction set.

Codex-specific reminders:

- Inspect the nearest applicable `AGENTS.md` before editing a subtree.
- Use repository-native tools and focused tests while iterating; run the gates required by `AGENTS.md` before handoff.
- Keep commentary concise, but surface safety assumptions, external mutations, and blockers before acting on them.
- Do not publish local opsctl state, production evidence, credentials, generated output, or ignored files.
- Git push, release/tag creation, Cloudflare deployment, and production execution require explicit user authorization.

If this file and `AGENTS.md` appear to differ, follow the stricter safety constraint and treat `AGENTS.md` as the source to update.
