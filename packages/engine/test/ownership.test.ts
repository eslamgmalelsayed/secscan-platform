import { describe, it, expect } from 'vitest';
import { AuthorizationGrant, verifyOwnership } from '../src';

const NOW = new Date();
function grant(proof: 'dns_txt' | 'http_token' | 'meta_tag', host = 'app.example.com') {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host }], ownershipProof: proof, ownershipToken: 'tok-123',
    chain: [{ party: 'A', email: 'a@a.sa', role: 'requester', signedAt: NOW.toISOString(), statement: 'r' }],
    notBefore: NOW.toISOString(), notAfter: NOW.toISOString(),
  });
}

describe('verifyOwnership', () => {
  it('dns_txt: accepts the token on _secscan.<host>, rejects a different token', async () => {
    const good = await verifyOwnership(grant('dns_txt'), { resolveTxt: async (n) => n.startsWith('_secscan.') ? [['secscan-verify=', 'tok-123']] : [] });
    expect(good.ok).toBe(true);
    const bad = await verifyOwnership(grant('dns_txt'), { resolveTxt: async () => [['secscan-verify=other']] });
    expect(bad.ok).toBe(false);
    expect(bad.detail.join()).not.toContain('tok-123'); // token never echoed
  });

  it('http_token: requires 200 and an exact body match at the well-known path', async () => {
    const seen: string[] = [];
    const ok = await verifyOwnership(grant('http_token'), { fetchText: async (u) => { seen.push(u); return { status: 200, body: 'tok-123\n' }; } });
    expect(ok.ok).toBe(true);
    expect(seen[0]).toBe('https://app.example.com/.well-known/secscan-verify.txt');
    const nf = await verifyOwnership(grant('http_token'), { fetchText: async () => ({ status: 404, body: '' }) });
    expect(nf.ok).toBe(false);
  });

  it('meta_tag: matches the content attribute on the root page', async () => {
    const ok = await verifyOwnership(grant('meta_tag'), { fetchText: async () => ({ status: 200, body: '<html><head><meta name="secscan-verify" content="tok-123"></head></html>' }) });
    expect(ok.ok).toBe(true);
    const bad = await verifyOwnership(grant('meta_tag'), { fetchText: async () => ({ status: 200, body: '<meta name="secscan-verify" content="nope">' }) });
    expect(bad.ok).toBe(false);
  });

  it('a network error is a failure, not a pass', async () => {
    const r = await verifyOwnership(grant('http_token'), { fetchText: async () => { throw new Error('ECONNREFUSED'); } });
    expect(r.ok).toBe(false);
  });
});
