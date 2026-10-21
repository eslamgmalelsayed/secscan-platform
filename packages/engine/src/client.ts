/**
 * The only way the engine sends traffic. Every replay goes through here, so
 * no check can bypass the scope gate — safety is a property of the plumbing,
 * not of each check author remembering it (Design §3, §8).
 */
import type { Identity, RecordedRequest, RecordedResponse } from './http';
import { classify } from './classifier';
import { ScopeGuard } from './scope';

/** A transport: performs the request for an identity. Injected (testable). */
export type Sender = (req: RecordedRequest, identity: Identity) => Promise<RecordedResponse>;

export class ScopeRefused extends Error {
  constructor(public decision: string, public reason: string) {
    super(`${decision}: ${reason}`);
    this.name = 'ScopeRefused';
  }
}

export class GuardedClient {
  readonly refused: ScopeRefused[] = [];

  constructor(private scope: ScopeGuard, private sender: Sender) {}

  async send(req: RecordedRequest, identity: Identity): Promise<RecordedResponse> {
    const isStateChanging = classify(req) === 'state_changing';
    const verdict = this.scope.check(req.url, req.method, { isStateChanging });
    if (!verdict.allowed) {
      const r = new ScopeRefused(verdict.decision, verdict.reason);
      this.refused.push(r);
      throw r;
    }
    return this.sender(req, identity);
  }
}
