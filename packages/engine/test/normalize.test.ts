import { describe, it, expect } from 'vitest';
import { bodyDigest, normalizeBody, requestHasObjectIdentifier } from '../src';

const J = 'application/json';

describe('normalizeBody (JSON)', () => {
  it('keeps entity identifiers: bodies differing only in `id` are NOT equal', () => {
    const a = JSON.stringify({ id: '6f1c2a3e-1111-4c5d-8e9f-aaaaaaaaaaaa', name: 'x' });
    const b = JSON.stringify({ id: '7a2d3b4f-2222-4c5d-8e9f-bbbbbbbbbbbb', name: 'x' });
    expect(bodyDigest(a, J)).not.toBe(bodyDigest(b, J));
  });

  it('still ignores volatile keys (request ids, timestamps, tokens) in both snake and camel case', () => {
    const a = JSON.stringify({ order: 42, request_id: 'aaa', created_at: '2026-01-01T00:00:00Z', csrfToken: 'x', updatedAt: '2026-01-01T00:00:00Z' });
    const b = JSON.stringify({ order: 42, request_id: 'bbb', created_at: '2026-02-02T00:00:00Z', csrfToken: 'y', updatedAt: '2026-03-03T00:00:00Z' });
    expect(bodyDigest(a, J)).toBe(bodyDigest(b, J));
  });

  it('still scrubs timestamps embedded in free-text values', () => {
    expect(normalizeBody('{"msg":"seen 2026-01-01T00:00:00Z"}', J)).toBe(normalizeBody('{"msg":"seen 2026-05-05T05:05:05Z"}', J));
  });
});

describe('requestHasObjectIdentifier', () => {
  it.each([
    ['https://a/orders/42', true],
    ['https://a/users/6f1c2a3e-1111-4c5d-8e9f-aaaaaaaaaaaa', true],
    ['https://a/files/9f86d081884c7d65', true],
    ['https://a/orders?id=42', true],
    ['https://a/x?user_id=7', true],
    ['https://a/api/me', false],
    ['https://a/dashboard', false],
    ['https://a/orders?page=1', false],
    ['https://a/v2/profile', false],
  ])('%s -> %s', (url, expected) => {
    expect(requestHasObjectIdentifier({ method: 'GET', url })).toBe(expected);
  });

  it('detects identifiers in a JSON body', () => {
    expect(requestHasObjectIdentifier({ method: 'POST', url: 'https://a/lookup', body: '{"orderId":42}' })).toBe(true);
    expect(requestHasObjectIdentifier({ method: 'POST', url: 'https://a/lookup', body: '{"q":"hello"}' })).toBe(false);
  });
});
