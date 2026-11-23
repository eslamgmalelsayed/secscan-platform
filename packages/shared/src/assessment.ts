import { z } from 'zod';

const label = z.string().trim().min(1).max(240);
const note = z.string().trim().min(1).max(2400);
export const domains = [
  'Web/API',
  'Network/WiFi',
  'Cloud/IAM',
  'Code',
  'Android',
  'iOS',
  'Business logic',
] as const;
export const projectInput = z.object({
  name: label,
  assets: z.array(label).min(1).max(100),
  authorization: label,
  expires: z.string().datetime(),
});
export const caseInput = z.object({ asset: label, domain: z.enum(domains), title: label, expected: note });
export const outcomes = ['pass', 'fail', 'inconclusive'] as const;
export const roles = ['tester', 'reviewer', 'reader'] as const;
export const importFormats = [
  'sarif',
  'openapi',
  's3',
  'android',
  'ios',
  'isolation',
  'https',
  'cyclonedx',
  'secscan',
  'wifi',
  'iam',
] as const;
export const operation = z.discriminatedUnion('type', [
  z.object({ type: z.literal('member'), name: label, role: z.enum(roles).nullable() }),
  z.object({ type: z.literal('plan'), cases: z.array(caseInput).min(1).max(500) }),
  z.object({
    type: z.literal('observe'),
    caseId: z.string().uuid(),
    outcome: z.enum(outcomes),
    context: label,
    evidence: note,
    baseline: note.optional(),
    attachment: z.string().max(64_000).optional(),
  }),
  z.object({
    type: z.literal('review'),
    caseId: z.string().uuid(),
    observationId: z.string().uuid(),
    approve: z.boolean(),
    reason: note,
    assignee: label.optional(),
  }),
  z.object({
    type: z.literal('import'),
    format: z.enum(importFormats),
    asset: label,
    context: label,
    data: z.unknown(),
  }),
  z.object({ type: z.literal('publish') }),
]);
export type Operation = z.infer<typeof operation>;
export type CaseInput = z.infer<typeof caseInput>;
export type Role = (typeof roles)[number] | 'owner';
export type Outcome = (typeof outcomes)[number];
export type Observation = {
  id: string;
  at: string;
  actor: string;
  outcome: Outcome;
  context: string;
  evidence: string;
  baseline?: string;
  attachment?: string;
  review?: { at: string; actor: string; approve: boolean; reason: string; assignee?: string };
};
export type TestCase = CaseInput & {
  id: string;
  observations: Observation[];
  state: 'planned' | 'passed' | 'open' | 'fixed';
  assignee?: string;
};
export type Project = z.infer<typeof projectInput> & {
  id: string;
  revision: number;
  owner: string;
  members: { name: string; role: Role }[];
  cases: TestCase[];
  history: { at: string; actor: string; action: string }[];
  reports: { id: string; at: string; revision: number; ar: string; en: string }[];
};
export function coverage(cases: TestCase[]) {
  const result = { planned: 0, pending: 0, completed: 0, inconclusive: 0 };
  for (const item of cases) {
    const latest = item.observations.at(-1);
    if (!latest) result.planned++;
    else if (!latest.review?.approve) result.pending++;
    else if (latest.outcome === 'inconclusive') result.inconclusive++;
    else result.completed++;
  }
  return result;
}
