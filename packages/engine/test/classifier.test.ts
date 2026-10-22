import { describe, it, expect } from 'vitest';
import { classify, replayableAgainstProduction } from '../src';

describe('classify', () => {
  it('flags a destructive GET as state-changing', () => {
    expect(classify({ method: 'GET', url: 'https://app.example.com/account/delete?id=5' })).toBe('state_changing');
  });
  it('treats a plain GET as safe', () => {
    expect(classify({ method: 'GET', url: 'https://app.example.com/orders/42' })).toBe('safe');
    expect(replayableAgainstProduction({ method: 'GET', url: 'https://app.example.com/orders/42' })).toBe(true);
  });
  it('matches whole words only: reads that merely contain a hint are safe', () => {
    for (const u of ['https://a/presets', 'https://a/players?page=2', 'https://a/api/users?remove_filter=0', 'https://a/display'])
      expect(classify({ method: 'GET', url: u }), u).toBe('safe');
  });
  it('catches mutating GETs by path word or action value', () => {
    for (const u of ['https://a/orders/42/cancel', 'https://a/approve?id=1', 'https://a/auth/logout', 'https://a/items?action=delete'])
      expect(classify({ method: 'GET', url: u }), u).toBe('state_changing');
  });
  it('treats POST as state-changing', () => {
    expect(classify({ method: 'POST', url: 'https://app.example.com/api/items' })).toBe('state_changing');
  });
});
