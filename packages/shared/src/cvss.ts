/**
 * CVSS v3.1 base score + vector (first.org specification).
 * Pure, dependency-free. Findings carry a {score, vector} so reports and
 * triage share one definition instead of hand-waving severity.
 */
export interface Cvss31Metrics {
  AV: 'N' | 'A' | 'L' | 'P'; // Attack Vector
  AC: 'L' | 'H';             // Attack Complexity
  PR: 'N' | 'L' | 'H';       // Privileges Required
  UI: 'N' | 'R';             // User Interaction
  S: 'U' | 'C';              // Scope
  C: 'N' | 'L' | 'H';        // Confidentiality
  I: 'N' | 'L' | 'H';        // Integrity
  A: 'N' | 'L' | 'H';        // Availability
}

const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC = { L: 0.77, H: 0.44 };
const PR_U = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C = { N: 0.85, L: 0.68, H: 0.5 };
const UI = { N: 0.85, R: 0.62 };
const CIA = { N: 0, L: 0.22, H: 0.56 };

/** Round up to one decimal, per the CVSS 3.1 "roundup" definition. */
function roundup(x: number): number {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

export function cvss31(m: Cvss31Metrics): { score: number; vector: string } {
  const iss = 1 - (1 - CIA[m.C]) * (1 - CIA[m.I]) * (1 - CIA[m.A]);
  const impact = m.S === 'U'
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  const pr = (m.S === 'C' ? PR_C : PR_U)[m.PR];
  const exploitability = 8.22 * AV[m.AV] * AC[m.AC] * pr * UI[m.UI];
  let score: number;
  if (impact <= 0) score = 0;
  else if (m.S === 'U') score = roundup(Math.min(impact + exploitability, 10));
  else score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  const vector = `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
  return { score, vector };
}

/** Qualitative band for a base score (CVSS 3.1 rating scale). */
export function cvssSeverity(score: number): 'none' | 'low' | 'medium' | 'high' | 'critical' {
  if (score === 0) return 'none';
  if (score < 4) return 'low';
  if (score < 7) return 'medium';
  if (score < 9) return 'high';
  return 'critical';
}
