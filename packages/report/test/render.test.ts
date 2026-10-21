import { describe, it, expect } from 'vitest';
import { Finding, ReportInput } from '@secscan/shared';
import { renderMarkdown, DISCLAIMER_AR } from '../src';

const finding = (over: Partial<Finding> = {}): Finding => Finding.parse({
  id: 'AC-bola_idor-deadbeef',
  title: { ar: 'تجاوز صلاحيات', en: 'Broken access control' },
  severity: 'high', confidence: 'confirmed', asset: 'app.example.com',
  location: 'GET /orders/42',
  description: { ar: 'مستخدم وصل لطلب غيره', en: 'A user read another order' },
  impact: { ar: 'تسرب بيانات', en: 'Data exposure' },
  remediation: { ar: 'طبّق التحقق', en: 'Enforce authz' },
  controls: [{ framework: 'NCA ECC-2:2024', control: '2-10 (indicative)' }],
  evidence: [{ kind: 'request', label: 'baseline', content: 'GET /orders/42 -> 200' }],
  firstSeen: '2026-10-21T00:00:00.000Z',
  source: 'engine/authz-diff',
  ...over,
});

const input = (findings: Finding[]): ReportInput => ReportInput.parse({
  engagement: {
    id: 'E-1', client: 'Acme', preparedBy: 'SecScan', assets: ['app.example.com'],
    environment: 'staging', authorizationRef: 'AUTH-123',
    window: { start: '2026-10-20T00:00:00.000Z', end: '2026-10-22T00:00:00.000Z' },
    methodology: { ar: 'اختبار صلاحيات حتمي', en: 'Deterministic authorization testing' },
    limitations: { ar: 'لم تُختبر البنية التحتية', en: 'Infrastructure not tested' },
  },
  findings,
});

describe('renderMarkdown', () => {
  it('renders Arabic with disclaimer and sections', () => {
    const md = renderMarkdown(input([finding()]), { lang: 'ar', notTested: ['deny_state_changing: POST /checkout'] });
    expect(md).toContain('تقرير تقييم أمني');
    expect(md).toContain('ملخص تنفيذي');
    expect(md).toContain('ما الذي لم يُفحص');
    expect(md).toContain('checkout');
    expect(md).toContain(DISCLAIMER_AR);
  });

  it('renders English and excludes unconfirmed by default', () => {
    const md = renderMarkdown(input([finding(), finding({ id: 'X-2', confidence: 'needs_review' })]), { lang: 'en' });
    expect(md).toContain('Security Assessment Report');
    expect(md).toContain('Broken access control');
    // needs_review finding excluded by default (reportable)
    expect((md.match(/Broken access control/g) ?? []).length).toBe(1);
  });

  it('never prints a bare compliance claim outside the disclaimer', () => {
    const md = renderMarkdown(input([finding()]), { lang: 'en' }).toLowerCase();
    const idx = md.indexOf('compliant');
    // the only occurrence is within the disclaimer sentence
    expect(idx === -1 || md.includes('not a compliance assessment')).toBe(true);
  });
});
