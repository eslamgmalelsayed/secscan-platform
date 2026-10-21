import { describe, it, expect } from 'vitest';
import { createHttpSender, SecretStore, type Identity } from '../src';

describe('createHttpSender', () => {
  it('applies identity cookie + bearer, does not follow redirects, returns body', async () => {
    const store = new SecretStore();
    store.put('sess-alice', { cookies: { session: 'alice' }, bearer: 'TOK', headers: { 'x-team': 'eng' } });
    let captured: { url: string; init: RequestInit } | null = null;
    const fakeFetch = (async (url: any, init: any) => {
      captured = { url, init };
      return new Response('{"ok":true}', { status: 200, headers: { 'content-type': 'application/json' } });
    }) as unknown as typeof fetch;

    const sender = createHttpSender({ store, fetchImpl: fakeFetch });
    const alice: Identity = { role: 'user', tenant: 't1', sessionRef: 'sess-alice' };
    const resp = await sender({ method: 'GET', url: 'https://app.example.com/me' }, alice);

    expect(resp.status).toBe(200);
    expect(resp.body).toContain('ok');
    const h = captured!.init.headers as Record<string, string>;
    expect(h['cookie']).toContain('session=alice');
    expect(h['authorization']).toBe('Bearer TOK');
    expect(h['x-team']).toBe('eng');
    expect(captured!.init.redirect).toBe('manual');
  });

  it('anonymous identity sends no auth material', async () => {
    let captured: any = null;
    const fakeFetch = (async (_url: any, init: any) => { captured = init; return new Response('', { status: 204 }); }) as unknown as typeof fetch;
    const sender = createHttpSender({ fetchImpl: fakeFetch });
    await sender({ method: 'GET', url: 'https://app.example.com/' }, { role: 'anonymous', sessionRef: null });
    const h = captured.headers as Record<string, string>;
    expect(h['cookie']).toBeUndefined();
    expect(h['authorization']).toBeUndefined();
  });

  it('transport error becomes status 0', async () => {
    const fakeFetch = (async () => { throw new Error('boom'); }) as unknown as typeof fetch;
    const sender = createHttpSender({ fetchImpl: fakeFetch });
    const resp = await sender({ method: 'GET', url: 'https://app.example.com/' }, { role: 'anonymous' });
    expect(resp.status).toBe(0);
  });
});
