/**
 * The unit the engine operates on. The platform never invents traffic: the
 * owner records real flows (logged in as each test identity) and the engine
 * replays THOSE requests under other identities. (Design §7, §11.)
 */
export interface RecordedRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | null;
  /** Which identity captured this, so a replay can be attributed/compared. */
  capturedAsRole?: string;
  capturedAsTenant?: string | null;
  /**
   * Owner's assertion that this flow MUST require authentication. The oracle
   * for missing-auth findings: black-box inference cannot tell a deliberately
   * public page from a should-be-private one, so the owner labels it. (§6/§9.)
   */
  requiresAuth?: boolean;
}

export interface RecordedResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** A test identity the owner supplied; secrets live in a store, not here (§7). */
export interface Identity {
  role: string;
  tenant?: string | null;
  sessionRef?: string | null; // opaque handle into the secret store
}

export const isAnonymous = (i: Identity): boolean => !i.sessionRef;
