import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { AuthorizationGrant, GuardedClient, ScopeGuard, createHttpSender, SecretStore, type RecordedRequest } from '@secscan/engine';
import { weakSessionToken, analyzeMobileArtifact, proveImpact, registerHandler, type CheckContext, type ExploitPolicy } from '../src';
import type { Finding } from '@secscan/shared';

const NOW = new Date();

// ---- session token ----
let srv: Server; let base: string;
beforeAll(async () => {
  srv = createServer((req, res) => {
    const p = new URL(req.url ?? '/', 'http://x').pathname;
    if (p === '/weak') { res.setHeader('Set-Cookie', ['sid=1042']); res.writeHead(200, { 'content-type': 'text/html' }); return res.end('ok'); }
    res.setHeader('Set-Cookie', ['sid=9f2b8c1a7e4d60b3f5a1c9e2d4b6081739ac5e2f']); // 40 hex chars, strong
    res.writeHead(200, { 'content-type': 'text/html' }); res.end('ok');
  });
  await new Promise<void>((r) => srv.listen(0, '127.0.0.1', () => r()));
  base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
});
afterAll(() => srv.close());

function ctxFor(rootPath: string): CheckContext {
  const grant = AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host: '127.0.0.1', scheme: 'http' }], ownershipProof: 'http_token', ownershipToken: 't',
    chain: [{ party: 'O', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'ok' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(), notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(), status: 'active',
  });
  const client = new GuardedClient(new ScopeGuard([grant], { blockPrivateAddresses: false }), createHttpSender({ store: new SecretStore() }));
  return { client, grantFingerprint: 'fp', rootUrl: `${base}${rootPath}`, flows: [] };
}

describe('weak session token', () => {
  it('flags a short/low-entropy session cookie', async () => {
    const out = await weakSessionToken(ctxFor('/weak'));
    expect(out).toHaveLength(1);
    expect(out[0].title.en).toContain('Weak session token');
  });
  it('does not flag a strong random session cookie', async () => {
    expect(await weakSessionToken(ctxFor('/strong'))).toHaveLength(0);
  });
});

describe('static mobile analysis', () => {
  it('finds hardcoded secrets, cleartext config, exported components, and endpoints', () => {
    const r = analyzeMobileArtifact([
      { name: 'res/values/strings.xml', content: 'key AIzaSyA1234567890abcdefghijklmnopqrstuv0 end' },
      { name: 'AndroidManifest.xml', content: '<application android:usesCleartextTraffic="true"><activity android:name=".X" android:exported="true"/></application>' },
      { name: 'classes/Config.txt', content: 'base = https://api.myapp.example/v1/login and https://schemas.android.com/apk ignore' },
    ]);
    const cats = new Set(r.findings.map((f) => f.id.split('-')[1]));
    expect(cats.has('secret_exposure')).toBe(true);
    expect(cats.has('tls')).toBe(true);           // cleartext
    expect(cats.has('access_control')).toBe(true); // exported component
    expect(r.endpoints).toContain('https://api.myapp.example');
    expect(r.endpoints.some((e) => e.includes('schemas.android.com'))).toBe(false);
  });
});

describe('gated proof-of-impact', () => {
  const confirmed: Finding = {
    id: 'CHK-injection-deadbeef', title: { ar: 'x', en: 'SQLi' }, severity: 'critical', confidence: 'confirmed',
    asset: 'h', description: { ar: 'x', en: 'x' }, impact: { ar: 'x', en: 'x' }, remediation: { ar: 'x', en: 'x' },
    evidence: [], controls: [], source: 'checks', firstSeen: NOW.toISOString(),
  } as unknown as Finding;
  const off: ExploitPolicy = { enabled: false, allowStateChanging: true };
  const staging: ExploitPolicy = { enabled: true, allowStateChanging: true };
  const prod: ExploitPolicy = { enabled: true, allowStateChanging: false };

  it('is gated OFF by default — no proof, reason recorded', () => {
    const r = proveImpact([confirmed], off);
    expect(r.proofs).toHaveLength(0);
    expect(r.skipped[0].reason).toContain('gate off');
  });
  it('refuses on a non-staging grant', () => {
    expect(proveImpact([confirmed], prod).skipped[0].reason).toContain('staging');
  });
  it('produces a BOUNDED proof when enabled on staging', () => {
    const r = proveImpact([confirmed], staging);
    expect(r.proofs).toHaveLength(1);
    expect(r.proofs[0].bounded).toBe(true);
    expect(r.proofs[0].proof).toMatch(/no data/i);
  });
  it('honours per-finding consent and is extensible via registerHandler', () => {
    const withConsent: ExploitPolicy = { enabled: true, allowStateChanging: true, consent: new Set(['nope']) };
    expect(proveImpact([confirmed], withConsent).skipped[0].reason).toContain('consent');
    registerHandler('customcat', (f) => ({ findingId: f.id, category: 'customcat', bounded: true, proof: 'bounded' }));
    const custom = { ...confirmed, id: 'CHK-customcat-0000' } as Finding;
    expect(proveImpact([custom], staging).proofs).toHaveLength(1);
  });
  it('never proves a non-confirmed finding', () => {
    const likely = { ...confirmed, confidence: 'likely' } as Finding;
    expect(proveImpact([likely], staging).proofs).toHaveLength(0);
  });
});
