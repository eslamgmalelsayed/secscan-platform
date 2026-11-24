/**
 * The only way the engine sends traffic. Every replay goes through here, so
 * no check can bypass the scope gate — safety is a property of the plumbing,
 * not of each check author remembering it (Design §3, §8).
 */
import type { Identity, RecordedRequest, RecordedResponse } from './http';
import { classify } from './classifier';
import { ScopeGuard } from './scope';

export interface SendOptions {
  /** Connect to this address (already scope-checked) instead of re-resolving the host. */
  pinnedAddress?: string;
}

/** A transport: performs the request for an identity. Injected (testable). */
export type Sender = (req: RecordedRequest, identity: Identity, opts?: SendOptions) => Promise<RecordedResponse>;

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
    const verdict = await this.scope.check(req.url, req.method, { isStateChanging });
    if (!verdict.allowed) {
      const r = new ScopeRefused(verdict.decision, verdict.reason);
      this.refused.push(r);
      throw r;
    }
    return this.sender(req, identity, { pinnedAddress: verdict.address });
  }

  /**
   * Scope gate for probes that need their own socket (TLS handshake, WebSocket
   * upgrade, gRPC over HTTP/2). Same check and refusal log as `send`; returns
   * the address to connect to. ws:// and wss:// are checked as http:// and https://.
   */
  /** A live grant names this host. No DNS lookup and no connection. */
  coversHost(url: string): boolean {
    return this.scope.coversHost(url);
  }

  async authorize(url: string, method = 'GET'): Promise<{ address?: string }> {
    const checked = url.replace(/^ws(s?):/i, 'http$1:');
    const verdict = await this.scope.check(checked, method, { isStateChanging: false });
    if (!verdict.allowed) {
      const r = new ScopeRefused(verdict.decision, verdict.reason);
      this.refused.push(r);
      throw r;
    }
    return { address: verdict.address };
  }
}
