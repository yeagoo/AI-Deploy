import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../content/docs');
const locales = ['zh', 'en'] as const;
const secretAssignment = /\b(?:AWS_SECRET_ACCESS_KEY|RESTIC_PASSWORD|OPSCTL_[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD))\s*=\s*\S+/;

async function contentFiles(locale: (typeof locales)[number]) {
  return (await readdir(path.join(root, locale)))
    .filter((file) => file.endsWith('.mdx'))
    .sort();
}

const [zhFiles, enFiles] = await Promise.all(locales.map(contentFiles));

if (JSON.stringify(zhFiles) !== JSON.stringify(enFiles)) {
  console.error('Localized content slugs do not match.');
  console.error({ zh: zhFiles, en: enFiles });
  process.exit(1);
}

for (const locale of locales) {
  const meta = JSON.parse(await readFile(path.join(root, locale, 'meta.json'), 'utf8')) as {
    pages?: string[];
  };
  const declaredPages = (meta.pages ?? []).filter((item) => !item.startsWith('---')).sort();
  const slugs = zhFiles.map((file) => file.replace(/\.mdx$/, ''));

  if (JSON.stringify(declaredPages) !== JSON.stringify(slugs)) {
    console.error(`${locale}/meta.json page order does not match its localized documents.`);
    process.exit(1);
  }

  for (const file of zhFiles) {
    const content = await readFile(path.join(root, locale, file), 'utf8');
    if (secretAssignment.test(content)) {
      console.error(`Potential secret assignment found in ${locale}/${file}.`);
      process.exit(1);
    }
  }
}

console.log(`PASS: ${zhFiles.length} bilingual document slugs are aligned and secret-safe.`);
