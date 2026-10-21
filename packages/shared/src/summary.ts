import { Finding, Severity, SEVERITY_ORDER } from './finding';

export type SeverityCounts = Record<Severity, number>;

/** Counts open findings by severity (fixed / accepted / false positives excluded). */
export function countOpenBySeverity(findings: Finding[]): SeverityCounts {
  const counts = Object.fromEntries(SEVERITY_ORDER.map(s => [s, 0])) as SeverityCounts;
  for (const f of findings) if (f.status === 'open') counts[f.severity]++;
  return counts;
}

/** Highest severity first, then by id for a stable order. */
export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) || a.id.localeCompare(b.id),
  );
}

/** Findings that may go in a client report: confirmed only, unless explicitly included. */
export function reportable(findings: Finding[], includeUnconfirmed = false): Finding[] {
  return findings.filter(f => includeUnconfirmed || f.confidence === 'confirmed');
}
