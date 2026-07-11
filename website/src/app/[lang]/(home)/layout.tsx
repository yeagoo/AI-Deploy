import { HomeLayout } from 'fumadocs-ui/layouts/home';
import { notFound } from 'next/navigation';
import { baseOptions } from '@/lib/layout.shared';
import { isLocale } from '@/lib/i18n';

export default async function Layout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ lang: string }>;
}) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();

  return <HomeLayout {...baseOptions(lang)}>{children}</HomeLayout>;
}
