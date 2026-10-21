import { describe, it, expect } from 'vitest';
import { cvss31, cvssSeverity, controlsFor } from '../src';

describe('cvss31', () => {
  it('scores a classic critical vector (9.8)', () => {
    // CVE-style RCE: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    const r = cvss31({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'H', I: 'H', A: 'H' });
    expect(r.score).toBe(9.8);
    expect(r.vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
  });
  it('scores a BOLA-style high (confidentiality only, low privs) ', () => {
    const r = cvss31({ AV: 'N', AC: 'L', PR: 'L', UI: 'N', S: 'U', C: 'H', I: 'N', A: 'N' });
    expect(r.score).toBe(6.5); // medium/high boundary
    expect(cvssSeverity(r.score)).toBe('medium');
  });
  it('scores all-none as 0', () => {
    expect(cvss31({ AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'U', C: 'N', I: 'N', A: 'N' }).score).toBe(0);
  });
  it('bands scores correctly', () => {
    expect(cvssSeverity(0)).toBe('none');
    expect(cvssSeverity(3.9)).toBe('low');
    expect(cvssSeverity(6.9)).toBe('medium');
    expect(cvssSeverity(8.9)).toBe('high');
    expect(cvssSeverity(9.8)).toBe('critical');
  });
});

describe('controlsFor', () => {
  it('returns multi-framework refs for access control', () => {
    const c = controlsFor('access_control');
    const fw = c.map((x) => x.framework);
    expect(fw).toContain('NCA ECC-2:2024');
    expect(fw).toContain('OWASP ASVS 4.0');
    expect(fw).toContain('ISO/IEC 27001:2022');
    expect(fw).toContain('NIST CSF');
    expect(c.find((x) => x.framework === 'CWE')?.control).toBe('CWE-639');
  });
  it('ECC control is tagged as indicative', () => {
    expect(controlsFor('jwt').find((x) => x.framework.startsWith('NCA'))?.control).toContain('indicative');
  });
});
