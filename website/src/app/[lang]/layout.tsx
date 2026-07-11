import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/600.css';
import '../global.css';
import { RootProvider } from 'fumadocs-ui/provider/next';
import { i18nProvider } from 'fumadocs-ui/i18n';
import { notFound } from 'next/navigation';
import type { Metadata } from 'next';
import { i18n, isLocale } from '@/lib/i18n';
import { translations } from '@/lib/layout.shared';
import { StaticSearchDialog } from '@/components/static-search';

export const metadata: Metadata = {
  title: {
    default: 'opsctl — Deployment safety controller',
    template: '%s — opsctl',
  },
  description:
    'A read-only-first deployment safety controller for registry, backup, recovery, approval, and signed evidence.',
  metadataBase: new URL(process.env.NEXT_PUBLIC_SITE_URL ?? 'https://ai-deploy-7a3.pages.dev'),
  icons: {
    icon: '/icon.svg',
  },
};

export function generateStaticParams() {
  return i18n.languages.map((lang) => ({ lang }));
}

export default async function LocaleLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();

  return (
    <html lang={lang === 'zh' ? 'zh-Hans' : 'en'} suppressHydrationWarning>
      <body className="min-h-screen">
        <RootProvider
          i18n={i18nProvider(translations, lang)}
          search={{ SearchDialog: StaticSearchDialog }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
