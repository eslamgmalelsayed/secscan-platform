/**
 * Render a ReportInput (engagement + findings) into bilingual Markdown (§9).
 * Reuses @secscan/shared helpers so ordering and the "confirmed-only" rule
 * match everywhere. Always renders the engagement's limitations and an
 * explicit "what was not tested" section, plus the no-compliance disclaimer.
 */
import {
  type Finding, type ReportInput, type Severity,
  SEVERITY_ORDER, countOpenBySeverity, reportable, sortFindings,
} from '@secscan/shared';
import { DISCLAIMER_AR, DISCLAIMER_EN } from './disclaimer';

export type Lang = 'ar' | 'en';

export interface RenderOptions {
  lang?: Lang;
  notTested?: string[];      // scope refusals, verbatim
  includeUnconfirmed?: boolean;
}

const SEV_AR: Record<Severity, string> = {
  critical: 'حرجة', high: 'عالية', medium: 'متوسطة', low: 'منخفضة', info: 'معلومة',
};
const SEV_EN: Record<Severity, string> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info',
};

function sevLabel(s: Severity, lang: Lang): string {
  return (lang === 'ar' ? SEV_AR : SEV_EN)[s];
}

function findingBlock(f: Finding, lang: Lang): string {
  const L = (t: { ar: string; en: string }) => t[lang];
  const lines = [
    `### [${sevLabel(f.severity, lang)}] ${L(f.title)}`,
    '',
    lang === 'ar' ? `- **المورد:** ${f.asset}${f.location ? ` · ${f.location}` : ''}` : `- **Asset:** ${f.asset}${f.location ? ` · ${f.location}` : ''}`,
    lang === 'ar' ? `- **الوصف:** ${L(f.description)}` : `- **Description:** ${L(f.description)}`,
    lang === 'ar' ? `- **الأثر:** ${L(f.impact)}` : `- **Impact:** ${L(f.impact)}`,
    lang === 'ar' ? `- **الإصلاح:** ${L(f.remediation)}` : `- **Remediation:** ${L(f.remediation)}`,
    lang === 'ar'
      ? `- **الثقة:** ${f.confidence} · المراجع: ${f.controls.map((c) => `${c.framework} ${c.control}`).join('؛ ') || '—'}`
      : `- **Confidence:** ${f.confidence} · References: ${f.controls.map((c) => `${c.framework} ${c.control}`).join('; ') || '—'}`,
  ];
  if (f.evidence.length) {
    lines.push(lang === 'ar' ? '- **الدليل:**' : '- **Evidence:**');
    for (const e of f.evidence) lines.push(`    - ${e.label ? `${e.label}: ` : ''}${e.content}`);
  }
  return lines.join('\n');
}

export function renderMarkdown(input: ReportInput, opts: RenderOptions = {}): string {
  const lang: Lang = opts.lang ?? 'ar';
  const eng = input.engagement;
  const findings = sortFindings(reportable(input.findings, opts.includeUnconfirmed));
  const counts = countOpenBySeverity(findings);
  const sevSummary = SEVERITY_ORDER.filter((s) => counts[s] > 0)
    .map((s) => `${sevLabel(s, lang)}: ${counts[s]}`).join(' · ') || '—';
  const date = new Date().toISOString().slice(0, 10);
  const out: string[] = [];

  if (lang === 'ar') {
    out.push(
      `# تقرير تقييم أمني — ${eng.client}`,
      `**التاريخ:** ${date} · **البيئة:** ${eng.environment} · **مرجع التفويض:** ${eng.authorizationRef}  `,
      `**الأصول:** ${eng.assets.join('، ')}  `,
      `**النافذة:** ${eng.window.start.slice(0, 10)} → ${eng.window.end.slice(0, 10)} · **أعدّه:** ${eng.preparedBy}`,
      '', '## ملخص تنفيذي', `- حسب الخطورة: ${sevSummary}`, '',
      '## المنهجية', eng.methodology.ar, '',
      '## النتائج',
    );
    out.push(findings.length ? findings.map((f) => findingBlock(f, 'ar')).join('\n\n') : '_لا توجد نتائج مؤكدة._');
    out.push('', '## حدود التغطية — ما الذي لم يُفحص', eng.limitations.ar);
    out.push(...(opts.notTested?.length ? opts.notTested.map((r) => `- ${r}`) : ['- لا شيء خارج النطاق المصرّح به.']));
    out.push('', '---', `> ${DISCLAIMER_AR}`);
  } else {
    out.push(
      `# Security Assessment Report — ${eng.client}`,
      `**Date:** ${date} · **Environment:** ${eng.environment} · **Authorization ref:** ${eng.authorizationRef}  `,
      `**Assets:** ${eng.assets.join(', ')}  `,
      `**Window:** ${eng.window.start.slice(0, 10)} → ${eng.window.end.slice(0, 10)} · **Prepared by:** ${eng.preparedBy}`,
      '', '## Executive summary', `- By severity: ${sevSummary}`, '',
      '## Methodology', eng.methodology.en, '',
      '## Findings',
    );
    out.push(findings.length ? findings.map((f) => findingBlock(f, 'en')).join('\n\n') : '_No confirmed findings._');
    out.push('', '## Coverage limits — what was not tested', eng.limitations.en);
    out.push(...(opts.notTested?.length ? opts.notTested.map((r) => `- ${r}`) : ['- Nothing outside the authorized scope.']));
    out.push('', '---', `> ${DISCLAIMER_EN}`);
  }
  return out.join('\n') + '\n';
}
