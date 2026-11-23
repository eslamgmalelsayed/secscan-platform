import type { AttachmentStore } from '../persistence/attachments';
import { randomUUID } from 'node:crypto';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import {
  caseInput,
  coverage,
  operation,
  projectInput,
  type CaseInput,
  type Project,
  type TestCase,
} from '@secscan/shared';
import { importCases } from './assessmentImports';

export interface ProjectStore {
  list(): Promise<Project[]>;
  get(id: string): Promise<Project | undefined>;
  save(project: Project, previous: number): Promise<boolean>;
}
export class MemoryProjectStore implements ProjectStore {
  private rows = new Map<string, Project>();
  async list() {
    return structuredClone([...this.rows.values()]);
  }
  async get(id: string) {
    return structuredClone(this.rows.get(id));
  }
  async save(project: Project, previous: number) {
    if ((this.rows.get(project.id)?.revision ?? 0) !== previous) return false;
    this.rows.set(project.id, structuredClone(project));
    return true;
  }
}

// Apply before persistence. Operators must still minimize free-form notes.
function redact(value: string) {
  return value
    .replace(
      /^(\s*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key)\s*:\s*).*$/gim,
      '$1[redacted]',
    )
    .replace(/\bBearer\s+[a-z0-9._~+/=-]+/gi, 'Bearer [redacted]')
    .replace(/([?&](?:access_token|api_key|token|password)=)[^&#\s]+/gi, '$1[redacted]');
}
// Imported titles can exceed the 240-character label limit (long file paths or
// routes). Keep both ends: the rule or method at the start, the line at the end.
function fitTitle(value: string) {
  const title = value.trim();
  return title.length <= 240 ? title : title.slice(0, 120).trimEnd() + ' … ' + title.slice(-117).trimStart();
}
const memberRole = (p: Project, actor: string) =>
  p.owner === actor ? 'owner' : p.members.find((m) => m.name === actor)?.role;
function ensureCase(p: Project, data: CaseInput) {
  if (!p.assets.includes(data.asset)) throw new BadRequestException('Asset outside project scope');
  const existing = p.cases.find(
    (c) =>
      c.asset === data.asset &&
      c.domain === data.domain &&
      c.title === data.title &&
      c.expected === data.expected,
  );
  if (existing) return existing;
  if (p.cases.length >= 2000) throw new BadRequestException('Project case limit reached');
  const item: TestCase = { ...data, id: randomUUID(), state: 'planned', observations: [] };
  p.cases.push(item);
  return item;
}
export function report(p: Project, arabic: boolean) {
  const pick = (ar: string, en: string) => (arabic ? ar : en);
  const counts = coverage(p.cases);
  const states = { planned: 'مخططة', passed: 'اجتازت', open: 'مفتوحة', fixed: 'تم التحقق من الإصلاح' };
  const outcomes = { pass: 'مطابق', fail: 'مخالف', inconclusive: 'تعذّر التحقق' };
  const lines = [
    p.name,
    pick('مرجع التصريح', 'Authorization') + ' · ' + p.authorization,
    pick('الأصول', 'Assets') + ' · ' + p.assets.join(', '),
    pick('نهاية التصريح', 'Expiry') + ' · ' + p.expires,
    pick(
      'مكتمل / بانتظار المراجعة / متعذر / لم يبدأ',
      'Completed / awaiting review / inconclusive / unstarted',
    ) +
      ' · ' +
      [counts.completed, counts.pending, counts.inconclusive, counts.planned].join(' / '),
  ];
  for (const c of p.cases) {
    lines.push('', c.title + ' · ' + c.asset + ' · ' + (arabic ? states[c.state] : c.state), c.expected);
    if (c.assignee) lines.push(pick('مسؤول الإصلاح', 'Remediation owner') + ' · ' + c.assignee);
    for (const o of c.observations.filter((o) => o.review?.approve)) {
      lines.push([o.at, o.context, arabic ? outcomes[o.outcome] : o.outcome].join(' · '), o.evidence);
      if (o.baseline) lines.push(pick('دليل المقارنة', 'Control evidence') + ' · ' + o.baseline);
      lines.push(pick('مراجعة', 'Review') + ' · ' + o.review!.actor + ' · ' + o.review!.reason);
    }
  }
  return lines.join('\n');
}
export class Assessments {
  constructor(
    private store: ProjectStore,
    private attachments?: AttachmentStore,
  ) {}
  async attachment(actor: string, id: string, hash: string) {
    const p = await this.get(actor, id);
    const observation = p.cases.flatMap((c) => c.observations).find((o) => o.attachment === hash);
    if (!observation || !this.attachments) throw new NotFoundException('Attachment not found');
    const result = await this.attachments.read(id, hash);
    const rev = p.revision++;
    p.history.push({ at: new Date().toISOString(), actor, action: 'attachment access ' + hash });
    if (!(await this.store.save(p, rev))) throw new ConflictException('Reload project');
    return result;
  }
  async list(actor: string) {
    return (await this.store.list())
      .filter((p) => memberRole(p, actor))
      .map((p) => ({ id: p.id, name: p.name, revision: p.revision }));
  }
  async get(actor: string, id: string) {
    const p = await this.store.get(id);
    if (!p || !memberRole(p, actor)) throw new NotFoundException('Project not found');
    return p;
  }
  async create(actor: string, input: unknown) {
    const data = projectInput.parse(input);
    if (Date.parse(data.expires) <= Date.now()) throw new BadRequestException('Authorization has expired');
    const p: Project = {
      ...data,
      assets: [...new Set(data.assets)],
      id: randomUUID(),
      owner: actor,
      revision: 1,
      members: [],
      cases: [],
      reports: [],
      history: [{ at: new Date().toISOString(), actor, action: 'created' }],
    };
    if (!(await this.store.save(p, 0))) throw new ConflictException();
    return p;
  }
  async change(actor: string, id: string, revision: number, input: unknown) {
    const p = await this.get(actor, id);
    const role = memberRole(p, actor);
    if (role === 'reader') throw new ForbiddenException();
    if (revision !== p.revision) throw new ConflictException('Project changed. Reload before editing.');
    const action = operation.parse(input);
    const now = new Date().toISOString();
    if (['plan', 'observe', 'import'].includes(action.type) && Date.parse(now) >= Date.parse(p.expires))
      throw new ForbiddenException('Authorization has expired');
    let detail: string = action.type;
    if (action.type === 'member') {
      if (role !== 'owner' || action.name === p.owner) throw new ForbiddenException();
      p.members = p.members.filter((m) => m.name !== action.name);
      if (action.role) p.members.push({ name: action.name, role: action.role });
      detail += ' ' + action.name + ' ' + (action.role ?? 'removed');
    } else if (action.type === 'plan') {
      for (const row of action.cases) ensureCase(p, row);
    } else if (action.type === 'import') {
      if (!p.assets.includes(action.asset)) throw new BadRequestException('Asset outside project scope');
      const entries = importCases(action);
      if (entries.length > 500) throw new BadRequestException('Maximum 500 supported entries per import');
      detail +=
        ' ' +
        action.format +
        ' · ' +
        action.asset +
        ' · ' +
        redact(action.context) +
        ' · ' +
        entries.length +
        ' supported entries';
      for (const row of entries) {
        const parsed = caseInput.parse({ ...row, title: fitTitle(redact(row.title)) });
        const item = ensureCase(p, parsed);
        if (!row.outcome || !row.evidence) continue;
        const observation = {
          actor,
          context: redact(action.context),
          evidence: redact(row.evidence).slice(0, 2400),
          outcome: row.outcome,
        };
        if (
          item.observations.some(
            (o) =>
              o.context === observation.context &&
              o.evidence === observation.evidence &&
              o.outcome === observation.outcome,
          )
        )
          continue;
        item.observations.push({ ...observation, id: randomUUID(), at: now });
      }
    } else if (action.type === 'publish') {
      if (role !== 'reviewer' && role !== 'owner') throw new ForbiddenException();
      p.reports.push({
        id: randomUUID(),
        at: now,
        revision: p.revision,
        ar: report(p, true),
        en: report(p, false),
      });
    } else {
      const c = p.cases.find((c) => c.id === action.caseId);
      if (!c) throw new NotFoundException('Case not found');
      detail += ' ' + c.id;
      if (action.type === 'observe') {
        if (action.attachment && !this.attachments)
          throw new BadRequestException('Configure an evidence bucket to attach a text file');
        const attachment = action.attachment
          ? await this.attachments!.put(id, redact(action.attachment))
          : undefined;
        c.observations.push({
          attachment,
          id: randomUUID(),
          at: now,
          actor,
          context: redact(action.context),
          evidence: redact(action.evidence),
          outcome: action.outcome,
          baseline: action.baseline ? redact(action.baseline) : undefined,
        });
      } else {
        if (role !== 'reviewer' && role !== 'owner') throw new ForbiddenException();
        const o = c.observations.at(-1);
        if (!o || o.review || o.id !== action.observationId)
          throw new ConflictException('Review the current observation');
        if (action.approve && o.outcome === 'pass' && c.state === 'open' && !o.baseline) {
          throw new BadRequestException(
            'Closing a finding requires positive control evidence for this retest',
          );
        }
        o.review = {
          at: now,
          actor,
          approve: action.approve,
          reason: redact(action.reason),
          assignee: action.assignee,
        };
        if (action.approve && action.assignee) c.assignee = action.assignee;
        if (action.approve && o.outcome === 'fail') c.state = 'open';
        if (action.approve && o.outcome === 'pass')
          c.state = ['open', 'fixed'].includes(c.state) ? 'fixed' : 'passed';
      }
    }
    p.history.push({ at: now, actor, action: detail });
    p.revision++;
    if (Buffer.byteLength(JSON.stringify(p)) > 8_000_000)
      throw new BadRequestException('Project storage limit reached');
    if (!(await this.store.save(p, revision)))
      throw new ConflictException('Concurrent edit. Reload before editing.');
    return p;
  }
}
