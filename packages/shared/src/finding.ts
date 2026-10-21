import { z } from 'zod';

/** Text shown in both report languages. */
export const LocalizedText = z.object({ ar: z.string().min(1), en: z.string().min(1) });
export type LocalizedText = z.infer<typeof LocalizedText>;

export const Severity = z.enum(['critical', 'high', 'medium', 'low', 'info']);
export type Severity = z.infer<typeof Severity>;
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** How sure we are a finding is real. Only "confirmed" findings go to clients by default. */
export const Confidence = z.enum(['confirmed', 'likely', 'needs_review']);
export type Confidence = z.infer<typeof Confidence>;

export const FindingStatus = z.enum(['open', 'fixed', 'risk_accepted', 'false_positive']);
export type FindingStatus = z.infer<typeof FindingStatus>;

export const Evidence = z.object({
  kind: z.enum(['request', 'response', 'note', 'screenshot_ref']),
  label: z.string().optional(),
  content: z.string().max(200_000),
});

/** Link to a control in a framework. A reference, never a compliance claim. */
export const ControlRef = z.object({
  framework: z.string().min(1), // e.g. "NCA ECC-2:2024", "OWASP ASVS 5.0"
  control: z.string().min(1),
});

export const Retest = z.object({
  at: z.string().datetime(),
  result: z.enum(['fixed', 'still_open']),
  note: z.string().optional(),
});

export const Finding = z.object({
  id: z.string().min(1),
  title: LocalizedText,
  severity: Severity,
  cvss: z.object({ score: z.number().min(0).max(10), vector: z.string().optional() }).optional(),
  confidence: Confidence,
  status: FindingStatus.default('open'),
  asset: z.string().min(1),
  location: z.string().optional(),
  description: LocalizedText,
  impact: LocalizedText,
  remediation: LocalizedText,
  evidence: z.array(Evidence).default([]),
  controls: z.array(ControlRef).default([]),
  source: z.string().default('manual'), // tool or person that produced it
  firstSeen: z.string().datetime(),
  retests: z.array(Retest).default([]),
});
export type Finding = z.infer<typeof Finding>;

/** Metadata about the authorized assessment a report covers. */
export const Engagement = z.object({
  id: z.string().min(1),
  client: z.string().min(1),
  preparedBy: z.string().min(1),
  assets: z.array(z.string().min(1)).min(1),
  environment: z.enum(['staging', 'production', 'lab']),
  authorizationRef: z.string().min(1), // ID of the signed owner authorization
  window: z.object({ start: z.string().datetime(), end: z.string().datetime() }),
  methodology: LocalizedText,
  limitations: LocalizedText, // what was NOT covered — always stated
});
export type Engagement = z.infer<typeof Engagement>;

export const ReportInput = z.object({ engagement: Engagement, findings: z.array(Finding) });
export type ReportInput = z.infer<typeof ReportInput>;
