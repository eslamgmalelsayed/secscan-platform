import { describe, it, expect } from 'vitest';
import { loadIdentities, createHttpSender, type RecordedRequest } from '../src';

describe('loadIdentities', () => {
  const file = {
    'customer/t1': { cookies: { sid: 'alice' }, liveness: 'https://app.test/api/me' },
    'customer/t2': { headers: { 'x-api-key': 'k2' } },
    admin: { bearer: 'tok-admin' },
  };

  it('turns the map into identities keyed by sessionRef, secrets kept in the store', () => {
    const { identities, store, liveness } = loadIdentities(file);
    expect(identities).toEqual([
      { role: 'customer', tenant: 't1', sessionRef: 'customer/t1' },
      { role: 'customer', tenant: 't2', sessionRef: 'customer/t2' },
      { role: 'admin', tenant: null, sessionRef: 'admin' },
    ]);
    expect(store.material('customer/t1').cookies).toEqual({ sid: 'alice' });
    expect(liveness).toEqual({ 'customer/t1': 'https://app.test/api/me' });
    // no secret on the identity object
    expect(JSON.stringify(identities)).not.toContain('alice');
  });

  it('rejects an entry with no material', () => {
    expect(() => loadIdentities({ ghost: {} })).toThrow();
  });

  it('the http sender applies the stored material', async () => {
    const { store, identities } = loadIdentities(file);
    let seen: Record<string, string> = {};
    const fetchImpl = (async (_url: string, init: any) => {
      seen = init.headers;
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;
    const send = createHttpSender({ store, fetchImpl });
    const req: RecordedRequest = { method: 'GET', url: 'https://app.test/x' };
    await send(req, identities[0]);
    expect(seen['cookie']).toBe('sid=alice');
    await send(req, identities[2]);
    expect(seen['authorization']).toBe('Bearer tok-admin');
  });
});
