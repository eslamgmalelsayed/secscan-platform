import { describe, it, expect } from 'vitest';
import { ScanTelemetry, BudgetTracker } from '../src';

describe('ScanTelemetry', () => {
  it('computes cost per confirmed finding', () => {
    const t = new ScanTelemetry();
    t.recordCost(0.5); t.recordCost(0.5); t.recordConfirmed(); t.recordConfirmed();
    expect(t.costPerConfirmedFinding()).toBe(0.5);
    expect(t.snapshot().confirmedFindings).toBe(2);
  });
  it('returns null cost-per-finding with zero findings', () => {
    expect(new ScanTelemetry().costPerConfirmedFinding()).toBeNull();
  });
});

describe('BudgetTracker', () => {
  it('flags exhaustion on tokens or calls', () => {
    const b = new BudgetTracker({ maxTokens: 100, maxToolCalls: 5 });
    expect(b.exhausted).toBe(false);
    b.addTokens(100);
    expect(b.exhausted).toBe(true);
    const c = new BudgetTracker({ maxTokens: 100, maxToolCalls: 2 });
    c.addCall(); c.addCall();
    expect(c.exhausted).toBe(true);
  });
});
