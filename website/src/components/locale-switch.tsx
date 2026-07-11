'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Languages } from 'lucide-react';
import type { Locale } from '@/lib/i18n';

export function LocaleSwitch({ locale, label }: { locale: Locale; label: string }) {
  const pathname = usePathname();
  const target: Locale = locale === 'zh' ? 'en' : 'zh';
  const segments = pathname.split('/');
  segments[1] = target;
  const href = segments.join('/') || `/${target}`;

  return (
    <Link href={href} className="locale-switch" aria-label={`Switch language to ${label}`}>
      <Languages aria-hidden="true" size={15} strokeWidth={1.8} />
      <span>{label}</span>
    </Link>
  );
}
