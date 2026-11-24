/**
 * DNS-only checks: mail spoofing protection (SPF and DMARC) and subdomains
 * whose CNAME points at a provider resource that no longer exists. They query
 * the resolver, never the target, and run only for hosts a live grant names.
 * Mail records belong to the organizational domain, which is read publicly.
 */
import { promises as systemDns } from 'node:dns';
import { isIP } from 'node:net';
import type { Finding } from '@secscan/shared';
import { build, safeSend, type CheckContext } from './context';

const t = (ar: string, en: string) => ({ ar, en });

/** The resolver calls these checks use; injectable for tests. */
export interface DnsResolver {
  resolveTxt(name: string): Promise<string[][]>;
  resolveCname(name: string): Promise<string[]>;
  resolve4(name: string): Promise<string[]>;
  resolve6(name: string): Promise<string[]>;
}
const resolverOf = (ctx: CheckContext): DnsResolver => ctx.dns ?? systemDns;
const missing = (e: unknown) => ['ENOTFOUND', 'ENODATA', 'ENONAME'].includes((e as NodeJS.ErrnoException).code ?? '');

async function txt(dns: DnsResolver, name: string): Promise<string[] | null> {
  try { return (await dns.resolveTxt(name)).map((parts) => parts.join('')); }
  catch (e) { if (missing(e)) return []; return null; }
}

/** Special-use names (RFC 6761, .internal, .local) are never on public DNS. */
const SPECIAL_USE = /(^|\.)(localhost|test|invalid|example|internal|local|lan|home\.arpa)$/i;
export function isPublicName(host: string): boolean {
  return !isIP(host.replace(/^\[|\]$/g, '')) && host.includes('.') && !SPECIAL_USE.test(host.replace(/\.$/, ''));
}

const SECOND_LEVEL = new Set(['com', 'net', 'org', 'gov', 'edu', 'co', 'ac', 'sch', 'med']);
/** Best-effort organizational domain: last two labels, or three under com.sa, co.uk and similar. */
export function orgDomain(host: string): string | null {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  if (labels.length < 2 || !isPublicName(host)) return null;
  const take = labels.length >= 3 && labels.at(-1)!.length === 2 && SECOND_LEVEL.has(labels.at(-2)!) ? 3 : 2;
  return labels.slice(-take).join('.');
}

export async function emailSpoofing(ctx: CheckContext): Promise<Finding[]> {
  if (!ctx.client.coversHost(ctx.rootUrl)) return [];
  const domain = orgDomain(new URL(ctx.rootUrl).hostname);
  if (!domain) return [];
  const dns = resolverOf(ctx);
  const [spfRecords, dmarcRecords] = await Promise.all([txt(dns, domain), txt(dns, `_dmarc.${domain}`)]);
  const out: Finding[] = [];
  const add = (key: string, severity: 'high' | 'medium' | 'low', title: [string, string], detail: [string, string], evidence: string) =>
    out.push(build({
      category: 'email_auth', severity, confidence: 'confirmed',
      title: t(title[0], title[1]), description: t(detail[0], detail[1]),
      impact: t('يستطيع أي أحد إرسال بريد يبدو صادرًا من هذا النطاق (تصيّد).', 'Anyone can send mail that appears to come from this domain (phishing).'),
      remediation: t('انشر SPF ينتهي بـ -all أو ~all، وسجل DMARC بسياسة quarantine أو reject. النطاق الذي لا يرسل بريدًا ينشر v=spf1 -all وp=reject.', 'Publish SPF ending in -all or ~all and a DMARC record with p=quarantine or p=reject. A domain that sends no mail should publish v=spf1 -all and p=reject.'),
      asset: domain, location: `DNS TXT ${key === 'dmarc' || key === 'dmarc-none' ? '_dmarc.' : ''}${domain}`,
      evidence: [{ kind: 'response', label: 'TXT', content: evidence }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'U', C: 'N', I: 'L', A: 'N' },
      idSeed: `${domain}|mail|${key}`,
    }, ctx.grantFingerprint));

  if (spfRecords) {
    const spf = spfRecords.filter((r) => /^v=spf1(\s|$)/i.test(r));
    if (!spf.length) add('spf', 'low', ['لا يوجد سجل SPF', 'No SPF record'], [`${domain} لا ينشر سجل SPF.`, `${domain} publishes no SPF record.`], 'no v=spf1 record');
    else if (spf.length > 1) add('spf-multi', 'low', ['أكثر من سجل SPF', 'Multiple SPF records'], ['وجود أكثر من سجل يجعل SPF غير صالح (permerror).', 'More than one record makes SPF invalid (permerror).'], spf.join(' | '));
    else if (/\s\+all\b/i.test(spf[0])) add('spf-all', 'high', ['SPF يسمح لأي خادم (+all)', 'SPF allows any server (+all)'], ['+all يجيز البريد من أي عنوان.', '+all authorizes mail from any address.'], spf[0]);
    else if (/\s\?all\b/i.test(spf[0]) || !/\s[-~]all\b|redirect=/i.test(spf[0])) add('spf-soft', 'low', ['SPF لا يرفض المرسلين الآخرين', 'SPF does not reject other senders'], ['السجل ينتهي بـ ?all أو بلا all.', 'The record ends in ?all or has no all term.'], spf[0]);
  }
  if (dmarcRecords) {
    const dmarc = dmarcRecords.find((r) => /^v=DMARC1/i.test(r));
    const policy = dmarc?.match(/(?:^|;)\s*p\s*=\s*(\w+)/i)?.[1]?.toLowerCase();
    if (!dmarc) add('dmarc', 'medium', ['لا يوجد سجل DMARC', 'No DMARC record'], [`_dmarc.${domain} غير موجود.`, `_dmarc.${domain} does not exist.`], 'no v=DMARC1 record');
    else if (policy === 'none' || !policy) add('dmarc-none', 'low', ['سياسة DMARC لا تحجب شيئًا (p=none)', 'DMARC policy blocks nothing (p=none)'], ['p=none يراقب فقط ولا يرفض البريد المزيف.', 'p=none only monitors and does not reject spoofed mail.'], dmarc);
  }
  return out;
}

/** CNAME suffixes of providers where an unclaimed name can be registered by someone else. */
const PROVIDERS: { suffix: RegExp; name: string; unclaimed?: RegExp }[] = [
  { suffix: /\.s3[.-][\w.-]*amazonaws\.com$|\.s3\.amazonaws\.com$/, name: 'Amazon S3', unclaimed: /NoSuchBucket/ },
  { suffix: /\.github\.io$/, name: 'GitHub Pages', unclaimed: /There isn't a GitHub Pages site here/ },
  { suffix: /\.herokuapp\.com$|\.herokudns\.com$/, name: 'Heroku', unclaimed: /No such app|herokucdn\.com\/error-pages\/no-such-app/ },
  { suffix: /\.azurewebsites\.net$|\.cloudapp\.net$|\.cloudapp\.azure\.com$|\.trafficmanager\.net$|\.blob\.core\.windows\.net$|\.azureedge\.net$/, name: 'Microsoft Azure' },
  { suffix: /\.myshopify\.com$/, name: 'Shopify', unclaimed: /Sorry, this shop is currently unavailable/ },
  { suffix: /\.fastly\.net$/, name: 'Fastly', unclaimed: /Fastly error: unknown domain/ },
  { suffix: /\.pantheonsite\.io$/, name: 'Pantheon', unclaimed: /The gods are wise, but do not know of the site/ },
  { suffix: /\.zendesk\.com$/, name: 'Zendesk', unclaimed: /Help Center Closed/ },
  { suffix: /\.netlify\.app$|\.netlify\.com$/, name: 'Netlify' },
  { suffix: /\.vercel\.app$|\.now\.sh$/, name: 'Vercel' },
];

async function resolves(dns: DnsResolver, name: string): Promise<boolean | null> {
  const attempt = async (f: (n: string) => Promise<string[]>) => {
    try { return (await f(name)).length > 0; } catch (e) { return missing(e) ? false : null; }
  };
  const [v4, v6] = await Promise.all([attempt((n) => dns.resolve4(n)), attempt((n) => dns.resolve6(n))]);
  if (v4 || v6) return true;
  return v4 === false && v6 === false ? false : null;
}

export async function danglingCname(ctx: CheckContext): Promise<Finding[]> {
  const dns = resolverOf(ctx);
  const hosts = [...new Set([ctx.rootUrl, ...ctx.flows.map((f) => f.url)].map((u) => {
    try { return new URL(u).hostname; } catch { return ''; }
  }))].filter((h) => h && isPublicName(h) && ctx.client.coversHost(`https://${h}/`)).slice(0, 20);
  const out: Finding[] = [];
  for (const host of hosts) {
    let cname: string | undefined;
    try { cname = (await dns.resolveCname(host))[0]?.toLowerCase().replace(/\.$/, ''); } catch { continue; }
    if (!cname) continue;
    const provider = PROVIDERS.find((p) => p.suffix.test(cname!));
    if (!provider) continue;
    const live = await resolves(dns, cname);
    let signal = '';
    if (live === false) signal = `${cname} does not resolve (NXDOMAIN)`;
    else if (live && provider.unclaimed) {
      const r = await safeSend(ctx, { method: 'GET', url: `https://${host}/` });
      if (r && provider.unclaimed.test(r.body)) signal = `${provider.name} answers with its unclaimed-resource page`;
    }
    if (!signal) continue;
    out.push(build({
      category: 'subdomain_takeover', severity: 'high', confidence: 'likely',
      title: t(`نطاق فرعي معرّض للاستيلاء: ${host}`, `Subdomain open to takeover: ${host}`),
      description: t(`${host} يشير عبر CNAME إلى ${cname} على ${provider.name}، والمورد لم يعد موجودًا.`, `${host} points by CNAME to ${cname} on ${provider.name}, and that resource no longer exists.`),
      impact: t('من يسجّل المورد لدى المزوّد يتحكم بما يقدَّم على نطاقك، بما فيه الكوكيز والتصيّد.', 'Whoever claims the resource at the provider controls what is served on your name, including cookies and phishing.'),
      remediation: t('احذف سجل CNAME أو أعد إنشاء المورد لدى المزوّد باسم حسابك.', 'Delete the CNAME record, or recreate the resource at the provider under your account.'),
      asset: host, location: `DNS CNAME ${host}`,
      evidence: [{ kind: 'response', label: 'dns', content: `CNAME ${host} → ${cname} · ${signal}` }],
      cvss: { AV: 'N', AC: 'L', PR: 'N', UI: 'R', S: 'C', C: 'L', I: 'H', A: 'N' },
      idSeed: `${host}|takeover|${cname}`,
    }, ctx.grantFingerprint));
  }
  return out;
}
