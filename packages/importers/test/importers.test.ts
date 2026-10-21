import { describe, it, expect } from 'vitest';
import { fromHar, fromOpenApi } from '../src';

const HAR = JSON.stringify({
  log: { entries: [
    { request: { method: 'GET', url: 'https://app.example.com/orders/42',
      headers: [{ name: 'Accept', value: 'application/json' }, { name: 'Cookie', value: 'session=secret' }, { name: ':method', value: 'GET' }] } },
    { request: { method: 'POST', url: 'https://app.example.com/checkout',
      headers: [{ name: 'Authorization', value: 'Bearer SECRET' }], postData: { text: '{"qty":1}' } } },
    { request: { method: 'GET', url: 'https://cdn.thirdparty.com/a.js', headers: [] } },
  ] },
});

describe('fromHar', () => {
  it('strips secrets and third-party hosts', () => {
    const flows = fromHar(HAR, { capturedAsRole: 'alice', capturedAsTenant: 't1', includeHosts: ['app.example.com'] });
    expect(flows.map((f) => f.url)).not.toContain('https://cdn.thirdparty.com/a.js');
    expect(flows).toHaveLength(2);
    const get = flows.find((f) => f.method === 'GET')!;
    expect(Object.keys(get.headers ?? {}).map((k) => k.toLowerCase())).not.toContain('cookie');
    expect(get.capturedAsRole).toBe('alice');
    const post = flows.find((f) => f.method === 'POST')!;
    expect(Object.keys(post.headers ?? {}).map((k) => k.toLowerCase())).not.toContain('authorization');
    expect(post.body).toBe('{"qty":1}');
  });
});

const SPEC = {
  openapi: '3.0.0',
  servers: [{ url: 'https://api.example.com/v1' }],
  paths: {
    '/items/{id}': { get: { parameters: [
      { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
      { name: 'expand', in: 'query', required: true, schema: { type: 'string' } },
    ], security: [{ bearer: [] }] } },
    '/health': { get: {} },
  },
};

describe('fromOpenApi', () => {
  it('builds requests and infers requiresAuth from security', () => {
    const flows = fromOpenApi(SPEC);
    const byUrl = Object.fromEntries(flows.map((f) => [f.url, f]));
    expect(byUrl['https://api.example.com/v1/items/1?expand=test']?.requiresAuth).toBe(true);
    expect(byUrl['https://api.example.com/v1/health']?.requiresAuth).toBe(false);
  });
  it('honors a base URL override', () => {
    const flows = fromOpenApi(SPEC, { baseUrl: 'https://staging.example.com' });
    expect(flows.some((f) => f.url.startsWith('https://staging.example.com/health'))).toBe(true);
  });
});
