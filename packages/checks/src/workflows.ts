/**
 * Static review of GitHub Actions workflow files you own. Reads text only:
 * nothing is run and no network call is made. Line-based on purpose (no YAML
 * dependency), so it looks for well-known risky shapes and reports the line.
 */
import { createHash } from 'node:crypto';
import type { Finding } from '@secscan/shared';
import { cvss31, controlsFor, Finding as FindingSchema, type Cvss31Metrics } from '@secscan/shared';

const t = (ar: string, en: string) => ({ ar, en });

export interface WorkflowFile { path: string; text: string }

/** Event fields an outside contributor controls. */
const UNTRUSTED = /\$\{\{\s*(github\.head_ref|github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label|head\.repo\.default_branch)|comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|pages\.[^}]*page_name|commits\.[^}]*\.(message|author\.(email|name))|head_commit\.(message|author\.(email|name))|workflow_run\.(head_branch|head_commit\.message)))\s*\}\}/;
const PR_HEAD = /github\.event\.pull_request\.head\.(sha|ref)|refs\/pull\/|github\.head_ref/;

function mk(file: string, line: number, args: {
  key: string; severity: 'high' | 'medium' | 'low'; confidence: 'confirmed' | 'likely' | 'needs_review';
  title: [string, string]; description: [string, string]; impact: [string, string]; remediation: [string, string];
  evidence: string; cvss: Cvss31Metrics;
}): Finding {
  return FindingSchema.parse({
    id: `CI-ci_cd-${createHash('sha256').update(`${file}|${args.key}|${line}`).digest('hex').slice(0, 8)}`,
    title: t(...args.title), severity: args.severity, confidence: args.confidence,
    asset: 'ci-workflows', location: `${file}:${line}`,
    description: t(...args.description), impact: t(...args.impact), remediation: t(...args.remediation),
    evidence: [{ kind: 'note', label: 'line', content: args.evidence.trim().slice(0, 300) }],
    cvss: cvss31(args.cvss), controls: controlsFor('ci_cd'),
    source: 'checks/workflows', firstSeen: new Date().toISOString(),
  });
}

const indent = (s: string) => s.match(/^\s*/)![0].length;

/** Lines that belong to a `run:` or github-script `script:` value, with their line numbers. */
function scriptLines(lines: string[]): [number, string][] {
  const out: [number, string][] = [];
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(\s*)(?:-\s+)?(run|script):\s*(.*)$/);
    if (!m) continue;
    const value = m[3];
    if (value && !/^[|>][+-]?\s*$/.test(value)) { out.push([i + 1, value]); continue; }
    const base = indent(lines[i]);
    for (let j = i + 1; j < lines.length && (lines[j].trim() === '' || indent(lines[j]) > base); j++) {
      if (lines[j].trim()) out.push([j + 1, lines[j]]);
      i = j;
    }
  }
  return out;
}

export function analyzeWorkflows(files: WorkflowFile[]): Finding[] {
  const out: Finding[] = [];
  for (const { path, text } of files) {
    const lines = text.split(/\r?\n/);
    const onBlock = text.match(/^on:([\s\S]*?)^(?=\S)/m)?.[1] ?? text.match(/^on:\s*(.*)$/m)?.[1] ?? '';
    const prTarget = /pull_request_target/.test(onBlock);
    const prEvent = /\bpull_request\b(?!_)/.test(onBlock) || prTarget;

    // 1. Script injection: attacker-controlled text expanded into a shell or script.
    for (const [n, line] of scriptLines(lines)) {
      const expr = line.match(UNTRUSTED)?.[1];
      if (!expr) continue;
      out.push(mk(path, n, {
        key: 'injection', severity: 'high', confidence: 'confirmed',
        title: ['حقن أوامر في سير عمل GitHub Actions', 'Command injection in a GitHub Actions workflow'],
        description: [`القيمة ${expr} يتحكم بها من يفتح الـ issue أو الـ PR، وتُدرج مباشرة في سكربت.`, `${expr} is controlled by whoever opens the issue or PR, and is expanded straight into a script.`],
        impact: ['تنفيذ أوامر على الـ runner مع صلاحيات GITHUB_TOKEN والأسرار المتاحة.', 'Runs commands on the runner with the GITHUB_TOKEN permissions and any secrets in scope.'],
        remediation: ['مرّر القيمة عبر env ثم استخدم "$VAR" مقتبسة داخل السكربت، ولا تكتب ${{ }} داخل run.', 'Pass the value through env and use the quoted "$VAR" in the script; never put ${{ }} inside run.'],
        evidence: line, cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },
      }));
    }

    // 2. pull_request_target that checks out the contributor's code.
    if (prTarget) {
      lines.forEach((line, i) => {
        if (!/uses:\s*actions\/checkout@/.test(line)) return;
        const block = lines.slice(i, i + 8).join('\n');
        if (!PR_HEAD.test(block)) return;
        out.push(mk(path, i + 1, {
          key: 'pwn-request', severity: 'high', confidence: 'confirmed',
          title: ['pull_request_target يشغّل كود الـ PR', 'pull_request_target checks out pull request code'],
          description: ['سير العمل يعمل بصلاحيات المستودع وأسراره، ويجلب كود المساهم الخارجي.', 'The workflow runs with repository permissions and secrets, and fetches the outside contributor\'s code.'],
          impact: ['أي PR من fork يستطيع تشغيل كوده بالأسرار وكتابة المستودع.', 'Any pull request from a fork can run its code with the secrets and write access.'],
          remediation: ['استخدم pull_request للبناء والاختبار، واترك pull_request_target لخطوات لا تشغّل كود الـ PR.', 'Use pull_request to build and test, and keep pull_request_target for steps that never run PR code.'],
          evidence: block.split('\n').find((l) => PR_HEAD.test(l)) ?? line,
          cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },
        }));
      });
    }

    // 3. Token permissions.
    const writeAll = lines.findIndex((l) => /^\s*permissions:\s*write-all\s*$/.test(l));
    if (writeAll >= 0) {
      out.push(mk(path, writeAll + 1, {
        key: 'write-all', severity: 'medium', confidence: 'confirmed',
        title: ['GITHUB_TOKEN بصلاحية write-all', 'GITHUB_TOKEN granted write-all'],
        description: ['كل خطوة تحصل على صلاحية كتابة كاملة على المستودع.', 'Every step gets full write access to the repository.'],
        impact: ['أي خطوة مخترقة تستطيع دفع كود أو تعديل الإصدارات.', 'Any compromised step can push code or alter releases.'],
        remediation: ['حدد الصلاحيات الدنيا لكل job، مثل contents: read.', 'Declare the minimum permissions per job, such as contents: read.'],
        evidence: lines[writeAll], cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'H', A: 'N' },
      }));
    } else if (!/^permissions:/m.test(text)) {
      out.push(mk(path, 1, {
        key: 'no-permissions', severity: 'low', confidence: 'needs_review',
        title: ['لا توجد صلاحيات صريحة لـ GITHUB_TOKEN', 'No explicit GITHUB_TOKEN permissions'],
        description: ['بلا مفتاح permissions في أعلى الملف، يحصل الرمز على صلاحيات المستودع الافتراضية، وقد تكون كتابة.', 'Without a top-level permissions key the token gets the repository default, which may be write.'],
        impact: ['صلاحيات أوسع من الحاجة لكل خطوة.', 'Broader access than each step needs.'],
        remediation: ['أضف permissions: contents: read في أعلى الملف وارفع الصلاحية لكل job عند الحاجة.', 'Add permissions: contents: read at the top and raise it per job only where needed.'],
        evidence: 'no top-level permissions key', cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'U', C: 'L', I: 'L', A: 'N' },
      }));
    }

    // 4. Self-hosted runners on pull request events.
    if (prEvent) {
      const runner = lines.findIndex((l) => /runs-on:.*self-hosted/.test(l));
      if (runner >= 0) out.push(mk(path, runner + 1, {
        key: 'self-hosted', severity: 'medium', confidence: 'needs_review',
        title: ['runner ذاتي الاستضافة على أحداث PR', 'Self-hosted runner on pull request events'],
        description: ['إن كان المستودع عامًا، يستطيع PR من fork تشغيل كود على جهازك.', 'If the repository is public, a pull request from a fork can run code on your machine.'],
        impact: ['اختراق الـ runner وشبكته، وبقاء الأثر بين التشغيلات.', 'Compromise of the runner and its network, persisting between runs.'],
        remediation: ['استخدم runners مستضافة لأحداث PR، أو اشترط موافقة قبل تشغيل PRs الخارجية.', 'Use hosted runners for PR events, or require approval before outside PRs run.'],
        evidence: lines[runner], cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'C', C: 'H', I: 'H', A: 'N' },
      }));
    }

    // 5. Third-party actions pinned to a movable tag or branch.
    lines.forEach((line, i) => {
      const m = line.match(/uses:\s*["']?([\w.-]+)\/([\w.\/-]+)@([\w.\/-]+)/);
      if (!m || ['actions', 'github'].includes(m[1].toLowerCase()) || /^[0-9a-f]{40}$/.test(m[3])) return;
      out.push(mk(path, i + 1, {
        key: `pin-${m[1]}/${m[2]}`, severity: 'low', confidence: 'confirmed',
        title: [`إجراء خارجي غير مثبّت بـ SHA: ${m[1]}/${m[2]}`, `Third-party action not pinned to a SHA: ${m[1]}/${m[2]}`],
        description: [`@${m[3]} وسم أو فرع يمكن لمالك الإجراء تغييره.`, `@${m[3]} is a tag or branch the action's owner can move.`],
        impact: ['اختراق مالك الإجراء يصل إلى سير عملك وأسراره.', 'A compromise of the action owner reaches your workflow and its secrets.'],
        remediation: ['ثبّت الإجراء على SHA الكامل للالتزام، واترك الوسم في تعليق.', 'Pin the action to the full commit SHA and keep the tag in a comment.'],
        evidence: line, cvss: { AV: 'N', AC: 'H', PR: 'N', UI: 'N', S: 'C', C: 'L', I: 'L', A: 'N' },
      }));
    });
  }
  return out;
}
