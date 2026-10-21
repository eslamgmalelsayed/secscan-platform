/**
 * Cost measurement from day one (Design §10).
 * The headline metric is cost per CONFIRMED finding — the number pricing will
 * be built on. Per-hypothesis budgets bound token/tool spend and stop early,
 * because failed attempts are the biggest source of waste.
 */
export interface HypothesisBudget {
  maxTokens: number;
  maxToolCalls: number;
}

export class ScanTelemetry {
  tokens = 0;
  toolCalls = 0;
  browserMs = 0;
  usd = 0;
  confirmedFindings = 0;

  recordTokens(n: number): void { this.tokens += n; }
  recordToolCall(n = 1): void { this.toolCalls += n; }
  recordBrowserMs(ms: number): void { this.browserMs += ms; }
  recordCost(usd: number): void { this.usd += usd; }
  recordConfirmed(n = 1): void { this.confirmedFindings += n; }

  costPerConfirmedFinding(): number | null {
    return this.confirmedFindings > 0 ? this.usd / this.confirmedFindings : null;
  }

  snapshot(): Record<string, number | null> {
    return {
      tokens: this.tokens,
      toolCalls: this.toolCalls,
      browserMs: this.browserMs,
      usd: Number(this.usd.toFixed(6)),
      confirmedFindings: this.confirmedFindings,
      costPerConfirmedFinding: this.costPerConfirmedFinding(),
    };
  }
}

/** Tracks spend for one hypothesis and tells the caller when to stop early. */
export class BudgetTracker {
  private tokens = 0;
  private calls = 0;
  constructor(private budget: HypothesisBudget) {}

  addTokens(n: number): void { this.tokens += n; }
  addCall(n = 1): void { this.calls += n; }

  get exhausted(): boolean {
    return this.tokens >= this.budget.maxTokens || this.calls >= this.budget.maxToolCalls;
  }
}
