/**
 * Windows binary (.exe/.dll) resilience — static PE-header analysis, offline.
 * For a binary YOU built: flags missing exploit mitigations (ASLR / DEP / CFG)
 * and whether it is Authenticode-signed. Pure parsing of the PE header; it never
 * runs the file. (Same spirit as the mobile resilience checks.)
 */
import type { Finding } from '@secscan/shared';
import { cvss31, controlsFor, Finding as FindingSchema } from '@secscan/shared';
import { createHash } from 'node:crypto';

const t = (ar: string, en: string) => ({ ar, en });

function mk(args: { severity: 'high' | 'medium' | 'low'; title: { ar: string; en: string }; description: { ar: string; en: string }; impact: { ar: string; en: string }; remediation: { ar: string; en: string }; idSeed: string }): Finding {
  return FindingSchema.parse({
    id: `BIN-security_header-${createHash('sha256').update(args.idSeed).digest('hex').slice(0, 8)}`,
    title: args.title, severity: args.severity, confidence: 'confirmed',
    asset: 'windows-binary', description: args.description, impact: args.impact, remediation: args.remediation,
    evidence: [{ kind: 'note', label: 'pe', content: args.idSeed }],
    cvss: cvss31({ AV: 'L', AC: 'H', PR: 'N', UI: 'R', S: 'U', C: 'L', I: 'H', A: 'N' }),
    controls: controlsFor('security_header'), source: 'checks/binary', firstSeen: new Date().toISOString(),
  });
}

export interface PeInfo { isPE: boolean; pe32Plus?: boolean; aslr?: boolean; dep?: boolean; cfg?: boolean; highEntropyVa?: boolean; signed?: boolean }

/** Parse the PE header enough to read mitigations + signature presence. */
export function parsePe(buf: Buffer): PeInfo {
  if (buf.length < 0x40 || buf.readUInt16LE(0) !== 0x5a4d) return { isPE: false }; // "MZ"
  const peOff = buf.readUInt32LE(0x3c);
  if (peOff + 0x78 > buf.length || buf.readUInt32LE(peOff) !== 0x00004550) return { isPE: false }; // "PE\0\0"
  const opt = peOff + 24; // optional header starts after the 24-byte COFF header
  const magic = buf.readUInt16LE(opt);
  const pe32Plus = magic === 0x20b;
  const dllChar = buf.readUInt16LE(opt + 0x46); // same offset for PE32 and PE32+
  const numRvaOff = opt + (pe32Plus ? 0x6c : 0x5c);
  const dirBase = opt + (pe32Plus ? 0x70 : 0x60);
  const certOff = dirBase + 4 * 8; // data directory index 4 = Certificate Table
  let signed = false;
  if (numRvaOff + 4 <= buf.length && buf.readUInt32LE(numRvaOff) > 4 && certOff + 8 <= buf.length) {
    signed = buf.readUInt32LE(certOff + 4) > 0; // Size field != 0 => embedded signature
  }
  return {
    isPE: true, pe32Plus,
    aslr: (dllChar & 0x0040) !== 0,
    dep: (dllChar & 0x0100) !== 0,
    cfg: (dllChar & 0x4000) !== 0,
    highEntropyVa: (dllChar & 0x0020) !== 0,
    signed,
  };
}

/** Resilience findings for a Windows binary you own. */
export function analyzeWindowsBinary(buf: Buffer): { info: PeInfo; findings: Finding[] } {
  const info = parsePe(buf);
  const findings: Finding[] = [];
  if (!info.isPE) return { info, findings };

  if (!info.aslr) findings.push(mk({
    severity: 'medium', title: t('غياب ASLR (DYNAMIC_BASE)', 'ASLR not enabled (DYNAMIC_BASE)'),
    description: t('الملف لا يفعّل العشوائية في مواضع الذاكرة، فتصبح العناوين متوقّعة.', 'The binary does not enable address-space randomization, so memory addresses are predictable.'),
    impact: t('يسهّل استغلال ثغرات تلف الذاكرة.', 'Eases exploitation of memory-corruption bugs.'),
    remediation: t('اربط بـ /DYNAMICBASE (مفعّل افتراضيًا في أدوات البناء الحديثة).', 'Link with /DYNAMICBASE (default in modern toolchains).'), idSeed: 'no-aslr',
  }));
  if (!info.dep) findings.push(mk({
    severity: 'medium', title: t('غياب DEP (NX_COMPAT)', 'DEP not enabled (NX_COMPAT)'),
    description: t('الملف لا يطلب منع تنفيذ البيانات.', 'The binary does not opt into data-execution prevention.'),
    impact: t('يسمح بتنفيذ شيفرة من مناطق بيانات.', 'Allows code execution from data regions.'),
    remediation: t('اربط بـ /NXCOMPAT.', 'Link with /NXCOMPAT.'), idSeed: 'no-dep',
  }));
  if (!info.cfg) findings.push(mk({
    severity: 'low', title: t('غياب Control Flow Guard', 'Control Flow Guard not enabled'),
    description: t('لا حماية لتدفّق التحكّم (CFG).', 'No control-flow integrity (CFG) protection.'),
    impact: t('يسهّل هجمات إعادة توجيه التنفيذ.', 'Eases control-flow hijacking.'),
    remediation: t('اربط بـ /guard:cf.', 'Link with /guard:cf.'), idSeed: 'no-cfg',
  }));
  if (!info.signed) findings.push(mk({
    severity: 'medium', title: t('الملف غير موقّع (Authenticode)', 'Binary is not code-signed'),
    description: t('لا يوجد توقيع Authenticode مضمّن، فلا يمكن التحقق من المصدر أو السلامة.', 'No embedded Authenticode signature, so origin/integrity cannot be verified.'),
    impact: t('يسهّل انتحال أو تعديل الملف دون كشف.', 'Eases tampering/impersonation without detection.'),
    remediation: t('وقّع الملف بشهادة موثوقة؛ والأهم: تحقّق من التراخيص على الخادم لا على العميل.', 'Sign with a trusted certificate; and validate licensing server-side, not in the client.'), idSeed: 'unsigned',
  }));
  return { info, findings };
}
