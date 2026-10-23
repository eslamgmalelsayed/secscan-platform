/**
 * Endpoint discovery — turn one URL into a set of flows (review: one-step scan).
 *
 * The platform's deepest checks (authorization-diffing) still need the owner's
 * own recorded traffic and test identities. But the passive scorecard and the
 * non-destructive active checks only need a list of reachable endpoints, and a
 * tester who just wants to try the tool should not have to record a HAR first.
 *
 * It crawls the public surface from a root URL and returns GET flows:
 *   - same-origin only (never follows a link off the target host/scheme/port),
 *   - GET only (a crawler must never submit a form or trigger a state change),
 *   - bounded (a page and link budget), breadth-first, de-duplicated by path,
 *   - through the GuardedClient, so the scope gate and SSRF pin still apply.
 *
 * Depth (review fix): besides anchor/form links, it also pulls endpoint paths
 * out of inline + same-origin script bundles and other string literals (so a
 * JS-heavy SPA yields its API surface, not just its two static links), and
 * seeds from robots.txt, sitemap.xml, and an OpenAPI/Swagger document when
 * present. Static assets are ignored as scan targets.
 *
 * Discovered flows are ANONYMOUS and carry no owner label unless the crawl ran
 * as a supplied identity, so they drive the scorecard and active checks, never
 * a confirmed object-level finding without an explicit label.
 */
import type { GuardedClient } from './client';
import type { Identity, RecordedRequest } from './http';

export interface DiscoverOptions {
  maxPages?: number;   // pages FETCHED while crawling (default 40)
  maxFlows?: number;   // flows RETURNED (default 100)
  maxScripts?: number; // same-origin JS bundles fetched for endpoint mining (default 12)
  identity?: Identity;
  capturedAsRole?: string;
  capturedAsTenant?: string | null;
}

const ANON: Identity = { role: 'anonymous', sessionRef: null };
const LINK_RE = /\s(?:href|action)\s*=\s*["']([^"'#\s]+)["']/gi;
const SRC_RE = /\ssrc\s*=\s*["']([^"'#\s]+\.js(?:\?[^"'#\s]*)?)["']/gi;
// path/URL string literals in HTML or JS: "/api/x", '/users/1', "https://host/x"
const PATH_RE = /["'`](\/[A-Za-z0-9_][A-Za-z0-9_\-./]{0,160}|https?:\/\/[A-Za-z0-9.\-:]+\/[A-Za-z0-9_\-./]{0,160})["'`]/g;
const STATIC_EXT = /\.(?:js|css|png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|map|pdf|zip|gz|mp4|mp3|wasm|txt|xml)(?:$|\?)/i;

function sameOrigin(a: URL, b: URL): boolean { return a.protocol === b.protocol && a.host === b.host; }
function pathKey(u: URL): string { return `${u.protocol}//${u.host}${u.pathname}`; }
function isHtml(ct?: string): boolean { const c = (ct ?? '').toLowerCase(); return !ct || c.includes('html') || c.includes('xml'); }

function same(raw: string, base: URL): URL | null {
  if (/^(mailto:|tel:|javascript:|data:|#)/i.test(raw)) return null;
  let u: URL;
  try { u = new URL(raw, base); } catch { return null; }
  u.hash = '';
  return sameOrigin(u, base) ? u : null;
}
function matchAllCap(re: RegExp, text: string, base: URL, out: URL[]): void {
  for (const m of text.matchAll(re)) { const u = same(m[1], base); if (u) out.push(u); }
}

async function get(client: GuardedClient, url: string, identity: Identity): Promise<{ status: number; body: string; ct?: string } | null> {
  try {
    const r = await client.send({ method: 'GET', url }, identity);
    return { status: r.status, body: r.body, ct: r.headers['content-type'] ?? r.headers['Content-Type'] };
  } catch { return null; }
}

/** robots.txt + sitemap.xml + common OpenAPI docs → extra same-origin URLs. */
async function seedSources(client: GuardedClient, root: URL, identity: Identity): Promise<URL[]> {
  const out: URL[] = [];
  const robots = await get(client, `${root.origin}/robots.txt`, identity);
  if (robots && robots.status < 400) {
    for (const line of robots.body.split('\n')) {
      const m = line.match(/^\s*(?:Allow|Disallow|Sitemap)\s*:\s*(\S+)/i);
      if (m) { const u = same(m[1], root); if (u) out.push(u); }
    }
  }
  for (const sm of [`${root.origin}/sitemap.xml`, ...out.filter((u) => /sitemap/i.test(u.pathname)).map((u) => u.toString())].slice(0, 3)) {
    const r = await get(client, sm, identity);
    if (r && r.status < 400) for (const m of r.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) { const u = same(m[1], root); if (u) out.push(u); }
  }
  for (const doc of ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs']) {
    const r = await get(client, `${root.origin}${doc}`, identity);
    if (!r || r.status >= 400) continue;
    try {
      const spec = JSON.parse(r.body);
      const serverBase = spec.servers?.[0]?.url ?? '';
      for (const p of Object.keys(spec.paths ?? {})) { const u = same(`${serverBase}${p}`, root); if (u) out.push(u); }
      break; // one spec is enough
    } catch { /* not JSON */ }
  }
  return out;
}

export async function discoverFlows(
  client: GuardedClient,
  rootUrl: string,
  opts: DiscoverOptions = {},
): Promise<RecordedRequest[]> {
  const maxPages = Math.max(1, opts.maxPages ?? 40);
  const maxFlows = Math.max(1, opts.maxFlows ?? 100);
  const maxScripts = Math.max(0, opts.maxScripts ?? 12);
  const identity = opts.identity ?? ANON;

  let root: URL;
  try { root = new URL(rootUrl); } catch { return []; }

  const seen = new Set<string>();
  const queue: URL[] = [root];
  const scriptsSeen = new Set<string>();
  seen.add(pathKey(root));
  const flows: RecordedRequest[] = [];
  let fetched = 0;
  let scriptsFetched = 0;

  const enqueue = (u: URL) => {
    if (STATIC_EXT.test(u.pathname)) return;   // not a scan target
    const key = pathKey(u);
    if (seen.has(key)) return;
    seen.add(key);
    queue.push(u);
  };

  for (const u of await seedSources(client, root, identity)) enqueue(u);

  while (queue.length && fetched < maxPages && flows.length < maxFlows) {
    const url = queue.shift()!;
    const r = await get(client, url.toString(), identity);
    if (!r) continue;
    fetched++;
    if (r.status < 400) {
      flows.push({ method: 'GET', url: url.toString(), capturedAsRole: opts.capturedAsRole, capturedAsTenant: opts.capturedAsTenant ?? null });
    }
    if (!isHtml(r.ct)) continue;

    const links: URL[] = [];
    matchAllCap(LINK_RE, r.body, url, links);   // anchors / form actions
    matchAllCap(PATH_RE, r.body, url, links);   // path/URL string literals in the HTML
    for (const l of links) enqueue(l);

    // mine same-origin script bundles for endpoint paths (SPA API surface)
    if (scriptsFetched < maxScripts) {
      const scripts: URL[] = [];
      matchAllCap(SRC_RE, r.body, url, scripts);
      for (const s of scripts) {
        if (scriptsFetched >= maxScripts) break;
        const key = pathKey(s);
        if (scriptsSeen.has(key)) continue;
        scriptsSeen.add(key);
        const js = await get(client, s.toString(), identity);
        scriptsFetched++;
        if (js && js.status < 400) { const found: URL[] = []; matchAllCap(PATH_RE, js.body, url, found); for (const f of found) enqueue(f); }
      }
    }
  }
  return flows;
}
