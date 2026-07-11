import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';
import { i18n } from '@/lib/i18n';

export const dynamic = 'force-static';

export default function sitemap(): MetadataRoute.Sitemap {
  const base = process.env.NEXT_PUBLIC_SITE_URL ?? 'https://ai-deploy.pages.dev';
  const landingPages = i18n.languages.map((lang) => ({
    url: new URL(`/${lang}`, base).toString(),
    changeFrequency: 'weekly' as const,
    priority: 1,
  }));
  const docs = source.getPages().map((page) => ({
    url: new URL(page.url, base).toString(),
    changeFrequency: 'weekly' as const,
    priority: page.slugs.length === 0 ? 0.9 : 0.75,
  }));

  return [...landingPages, ...docs];
}
