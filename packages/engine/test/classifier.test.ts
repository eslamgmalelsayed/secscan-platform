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
  it('treats POST as state-changing', () => {
    expect(classify({ method: 'POST', url: 'https://app.example.com/api/items' })).toBe('state_changing');
  });
});
