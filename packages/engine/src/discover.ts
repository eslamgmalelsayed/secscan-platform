/**
 * Endpoint discovery — turn one URL into a set of flows (review: one-step scan).
 *
 * The platform's deepest checks (authorization-diffing) still need the owner's
 * own recorded traffic and test identities. But the passive scorecard and the
 * non-destructive active checks only need a list of reachable endpoints, and a
 * tester who just wants to try the tool should not have to record a HAR first.
 *
 * So this crawls the public surface from a root URL and returns GET flows:
 *   - same-origin only (never follows a link off the target host/scheme/port),
 *   - GET only (a crawler must never submit a form or trigger a state change),
 *   - bounded (a page and link budget), breadth-first, de-duplicated by path,
 *   - through the GuardedClient, so the scope gate and SSRF pin still apply to
 *     every fetch — discovery cannot reach anywhere a scan could not.
 *
 * Discovered flows are ANONYMOUS and carry no owner label, so they drive the
 * scorecard and active checks, never a confirmed object-level finding. To test
 * behind a login or to enable the IDOR engine the owner still supplies
 * identities (and, for confirmation, labels the owned-object flows).
 */
import type { GuardedClient } from './client';
import type { Identity, RecordedRequest } from './http';

export interface DiscoverOptions {
  /** Max pages to FETCH while crawling for links (default 40). */
  maxPages?: number;
  /** Max flows to RETURN (default 100). */
  maxFlows?: number;
  /** Identity to crawl as (default anonymous — the public surface). */
  identity?: Identity;
  /** Attribution stamped on every discovered flow, so a logged-in crawl can
   *  still feed the checks as that role. Discovery never sets `ownsObject`. */
  capturedAsRole?: string;
  capturedAsTenant?: string | null;
}

const ANON: Identity = { role: 'anonymous', sessionRef: null };
const HTML_RE = /\s(?:href|src|action)\s*=\s*["']([^"'#\s]+)["']/gi;

function sameOrigin(a: URL, b: URL): boolean {
  return a.protocol === b.protocol && a.host === b.host;
}

/** A page key that ignores the query, so `/p?a=1` and `/p?a=2` count once. */
function pathKey(u: URL): string {
  return `${u.protocol}//${u.host}${u.pathname}`;
}

function extractLinks(html: string, base: URL): URL[] {
  const out: URL[] = [];
  for (const m of html.matchAll(HTML_RE)) {
    const raw = m[1];
    if (/^(mailto:|tel:|javascript:|data:)/i.test(raw)) continue;
    let u: URL;
    try { u = new URL(raw, base); } catch { continue; }
    u.hash = '';
    if (sameOrigin(u, base)) out.push(u);
  }
  return out;
}

function isHtml(contentType: string | undefined): boolean {
  return !contentType || contentType.toLowerCase().includes('html') || contentType.toLowerCase().includes('xml');
}

/**
 * Crawl from `rootUrl` and return the GET flows found (including the root).
 * Fetches are best-effort: a failed or out-of-scope page is skipped, never
 * fatal, so discovery degrades to "just the pages I could reach".
 */
export async function discoverFlows(
  client: GuardedClient,
  rootUrl: string,
  opts: DiscoverOptions = {},
): Promise<RecordedRequest[]> {
  const maxPages = Math.max(1, opts.maxPages ?? 40);
  const maxFlows = Math.max(1, opts.maxFlows ?? 100);
  const identity = opts.identity ?? ANON;

  let root: URL;
  try { root = new URL(rootUrl); } catch { return []; }

  const seen = new Set<string>();     // page keys already queued/visited
  const queue: URL[] = [root];
  seen.add(pathKey(root));
  const flows: RecordedRequest[] = [];
  let fetched = 0;

  while (queue.length && fetched < maxPages && flows.length < maxFlows) {
    const url = queue.shift()!;
    let resp;
    try {
      resp = await client.send({ method: 'GET', url: url.toString() }, identity);
    } catch {
      continue; // scope refusal or transport error: skip this page
    }
    fetched++;
    flows.push({
      method: 'GET', url: url.toString(),
      capturedAsRole: opts.capturedAsRole, capturedAsTenant: opts.capturedAsTenant ?? null,
    });

    const ct = resp.headers['content-type'] ?? resp.headers['Content-Type'];
    if (!isHtml(ct)) continue;
    for (const link of extractLinks(resp.body, url)) {
      const key = pathKey(link);
      if (seen.has(key)) continue;
      seen.add(key);
      queue.push(link);
    }
  }
  return flows;
}
