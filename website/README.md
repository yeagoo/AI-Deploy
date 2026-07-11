# opsctl documentation platform

Bilingual Chinese/English product documentation built with Next.js 16, Fumadocs, Fumadocs MDX, Tailwind CSS 4, and Orama. The production build is a static export for Cloudflare Pages; search indexes are generated at build time and queried in the browser.

## Runtime

- Node.js 22 or newer for conventional Next.js workflows.
- Bun 1.3 or newer is supported for local development and is used by the lockfile.

## Development

```bash
cd website
bun install
bun run dev
```

Open:

- Chinese: <http://localhost:3000/zh>
- English: <http://localhost:3000/en>
- Chinese docs: <http://localhost:3000/zh/docs>
- English docs: <http://localhost:3000/en/docs>

## Quality checks

```bash
bun run lint
bun run types:check
bun run build
```

Or run all three:

```bash
bun run check
```

## Cloudflare Pages

The default production origin is `https://ai-deploy-7a3.pages.dev`. Override it for a custom domain with `NEXT_PUBLIC_SITE_URL` before building.

```bash
bun run check
bun run preview
bun run pages:deploy
```

Cloudflare Pages settings for Git integration:

- Root directory: `website`
- Build command: `bun run build`
- Build output directory: `out`
- Production branch: `main`

`public/_redirects` sends `/` to the default Chinese locale. Do not replace the static search route with a server-only endpoint; Pages must be able to serve the generated index without a Worker.

## Content structure

The site uses directory-based locale parsing with no fallback:

```text
content/docs/
├── zh/
│   ├── meta.json
│   └── *.mdx
└── en/
    ├── meta.json
    └── *.mdx
```

Every core guide must exist under both locales with the same slug. A missing translation is a build/content defect, not an invitation to mix languages on one page.

## Security boundary

Documentation may include environment variable names and placeholder IDs. It must not include credential values, live `.env` files, private repository URLs, production-only evidence paths, or approval tokens.

Set `NEXT_PUBLIC_SITE_URL` when using a custom origin so canonical and Open Graph metadata use the correct host.
