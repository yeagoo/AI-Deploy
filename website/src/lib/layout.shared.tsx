import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { uiTranslations } from 'fumadocs-ui/i18n';
import { zhCN } from '@fumadocs/language/zh-cn';
import { i18n } from './i18n';
import { BrandMark } from '@/components/brand-mark';

export const translations = i18n
  .translations()
  .extend(uiTranslations())
  .preset('zh', zhCN())
  .add({
    en: {
      displayName: 'English',
    },
  });

export function baseOptions(locale: string): BaseLayoutProps {
  const chinese = locale === 'zh';

  return {
    nav: {
      title: <BrandMark />,
      url: `/${locale}`,
    },
    links: [
      {
        text: chinese ? '文档' : 'Docs',
        url: `/${locale}/docs`,
        active: 'nested-url',
      },
      {
        text: chinese ? '安全模型' : 'Safety model',
        url: `/${locale}/docs/safety-model`,
      },
      {
        text: chinese ? '命令参考' : 'CLI reference',
        url: `/${locale}/docs/cli-reference`,
      },
    ],
  };
}
