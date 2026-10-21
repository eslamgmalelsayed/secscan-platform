import { describe, it, expect } from 'vitest';
import { Finding, countOpenBySeverity, sortFindings, reportable } from '../src';

const base = (over: Partial<Finding> = {}): Finding => Finding.parse({
  id: 'F-1', title: { ar: 'عنوان', en: 'Title' }, severity: 'high', confidence: 'confirmed',
  asset: 'app.example.com', description: { ar: 'و', en: 'd' }, impact: { ar: 'أ', en: 'i' },
  remediation: { ar: 'ص', en: 'r' }, firstSeen: '2026-10-01T00:00:00.000Z', ...over,
});

describe('summary helpers', () => {
  it('counts only open findings', () => {
    const c = countOpenBySeverity([base(), base({ id: 'F-2', status: 'fixed' }), base({ id: 'F-3', severity: 'low' })]);
    expect(c).toEqual({ critical: 0, high: 1, medium: 0, low: 1, info: 0 });
  });
  it('sorts by severity then id', () => {
    const s = sortFindings([base({ id: 'B', severity: 'low' }), base({ id: 'A', severity: 'critical' }), base({ id: 'C', severity: 'low' })]);
    expect(s.map(f => f.id)).toEqual(['A', 'B', 'C']);
  });
  it('excludes unconfirmed by default', () => {
    const r = reportable([base(), base({ id: 'F-2', confidence: 'needs_review' })]);
    expect(r.map(f => f.id)).toEqual(['F-1']);
  });
  it('rejects a finding with missing Arabic text', () => {
    expect(() => base({ title: { ar: '', en: 'x' } as any })).toThrow();
  });
});
