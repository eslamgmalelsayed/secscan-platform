import { describe, it, expect } from 'vitest';
import { AuthorizationGrant, ScopeGuard, isPrivateIp } from '../src';

const NOW = new Date();
const PUBLIC = () => ['93.184.216.34'];

function grant(host = 'app.example.com', o: { allowStateChanging?: boolean; active?: boolean } = {}) {
  return AuthorizationGrant.parse({
    grantId: 'g', targets: [{ host }], ownershipProof: 'dns_txt', ownershipToken: 't',
    chain: [{ party: 'Owner', email: 'o@o.sa', role: 'system_owner', signedAt: NOW.toISOString(), statement: 'authorized' }],
    notBefore: new Date(NOW.getTime() - 3.6e6).toISOString(),
    notAfter: new Date(NOW.getTime() + 3.6e6).toISOString(),
    allowStateChanging: o.allowStateChanging ?? false,
    status: o.active === false ? 'pending_owner' : 'active',
  });
}

describe('ScopeGuard', () => {
  it('denies out-of-scope host', () => {
    const g = new ScopeGuard([grant()], { resolveHost: PUBLIC });
    expect(g.check('https://evil.example.org/x', 'GET').decision).toBe('deny_no_grant');
  });
  it('denies state-changing without permission', () => {
    const g = new ScopeGuard([grant('app.example.com', { allowStateChanging: false })], { resolveHost: PUBLIC });
    expect(g.check('https://app.example.com/checkout', 'POST').decision).toBe('deny_state_changing');
  });
  it('allows state-changing with permission', () => {
    const g = new ScopeGuard([grant('app.example.com', { allowStateChanging: true })], { resolveHost: PUBLIC });
    expect(g.check('https://app.example.com/orders/1', 'PUT').allowed).toBe(true);
  });
  it('blocks private address even in scope', () => {
    const g = new ScopeGuard([grant()], { resolveHost: () => ['127.0.0.1'] });
    expect(g.check('https://app.example.com/x', 'GET').decision).toBe('deny_private_address');
  });
  it('denies when grant not live', () => {
    const g = new ScopeGuard([grant('app.example.com', { active: false })], { resolveHost: PUBLIC });
    expect(g.check('https://app.example.com/x', 'GET').decision).toBe('deny_grant_not_live');
  });
  it('allows an in-scope public GET', () => {
    const g = new ScopeGuard([grant()], { resolveHost: PUBLIC });
    expect(g.check('https://app.example.com/orders/42', 'GET').allowed).toBe(true);
  });
});

describe('isPrivateIp', () => {
  it('flags private/loopback/link-local/cgnat', () => {
    for (const ip of ['10.0.0.1', '127.0.0.1', '192.168.1.1', '172.16.0.1', '169.254.0.1', '100.64.0.1', '::1', 'fd00::1'])
      expect(isPrivateIp(ip)).toBe(true);
  });
  it('passes public addresses', () => {
    for (const ip of ['93.184.216.34', '8.8.8.8', '1.1.1.1']) expect(isPrivateIp(ip)).toBe(false);
  });
});
