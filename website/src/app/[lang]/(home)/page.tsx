import Link from 'next/link';
import { ArrowRight, Check, Terminal } from 'lucide-react';
import { notFound } from 'next/navigation';
import { LocaleSwitch } from '@/components/locale-switch';
import { isLocale } from '@/lib/i18n';
import { siteCopy } from '@/lib/site-copy';

export default async function HomePage({ params }: { params: Promise<{ lang: string }> }) {
  const { lang } = await params;
  if (!isLocale(lang)) notFound();
  const copy = siteCopy[lang];

  return (
    <main className="product-home">
      <section className="hero-shell">
        <div className="hero-grid" aria-hidden="true" />
        <div className="hero-meta">
          <span>{copy.eyebrow}</span>
          <LocaleSwitch locale={lang} label={copy.languageLabel} />
        </div>
        <div className="hero-copy">
          <p className="hero-kicker">
            <span className="status-dot" /> operational safety / evidence first
          </p>
          <h1>{copy.title}</h1>
          <p className="hero-deck">{copy.description}</p>
          <div className="hero-actions">
            <Link href={`/${lang}/docs/getting-started`} className="button button-primary">
              {copy.primaryCta} <ArrowRight size={17} />
            </Link>
            <Link href={`/${lang}/docs/safety-model`} className="button button-secondary">
              {copy.secondaryCta}
            </Link>
          </div>
        </div>
        <div className="control-card">
          <div className="control-card-head">
            <span>{copy.signalTitle}</span>
            <Terminal size={16} aria-hidden="true" />
          </div>
          <div className="control-command">
            <span>$</span> opsctl preflight plan.yml --json
          </div>
          <div className="control-status">
            {copy.signals.map(([code, label]) => (
              <div key={code}>
                <span className="control-code">{code}</span>
                <span className="control-label">
                  <Check size={13} /> {label}
                </span>
              </div>
            ))}
          </div>
          <div className="control-foot">
            <span>decision</span>
            <strong>NEEDS_APPROVAL</strong>
          </div>
        </div>
      </section>

      <section className="manifesto-section section-frame">
        <p className="section-index">01 / PRINCIPLE</p>
        <div>
          <h2>{copy.proofTitle}</h2>
          <p>{copy.proofBody}</p>
        </div>
      </section>

      <section className="workflow-section section-frame">
        <div className="section-heading">
          <p className="section-index">02 / WORKFLOW</p>
          <h2>{copy.workflowTitle}</h2>
        </div>
        <div className="workflow-grid">
          {copy.workflow.map(([number, title, body]) => (
            <article key={number}>
              <span>{number}</span>
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="capabilities-section section-frame">
        <div className="section-heading split-heading">
          <p className="section-index">03 / SURFACE</p>
          <h2>{copy.capabilitiesTitle}</h2>
        </div>
        <div className="capability-grid">
          {copy.capabilities.map(([title, body], index) => (
            <article key={title}>
              <span className="capability-number">{String(index + 1).padStart(2, '0')}</span>
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="safety-callout section-frame">
        <div className="hazard-mark" aria-hidden="true">
          !
        </div>
        <div>
          <p className="section-index">04 / BOUNDARY</p>
          <h2>{copy.calloutTitle}</h2>
          <p>{copy.calloutBody}</p>
        </div>
      </section>

      <section className="final-cta section-frame">
        <div>
          <p className="section-index">05 / BEGIN</p>
          <h2>{copy.finalTitle}</h2>
          <p>{copy.finalBody}</p>
        </div>
        <Link href={`/${lang}/docs/getting-started`} className="button button-primary">
          {copy.primaryCta} <ArrowRight size={17} />
        </Link>
      </section>

      <footer className="site-footer section-frame">
        <span>opsctl / documentation</span>
        <span>{copy.footer}</span>
        <span>{copy.languageName}</span>
      </footer>
    </main>
  );
}
