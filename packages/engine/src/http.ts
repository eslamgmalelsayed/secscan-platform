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
  /**
   * Owner's assertion that the object this request names BELONGS TO the
   * capturing identity — so another identity receiving the same body is a real
   * authorization break, not a legitimately shared resource. The oracle for
   * object-level findings: response comparison cannot tell a per-user object
   * (`/api/orders/42`) from one every authenticated user may rightly see
   * (`/api/products/42`); only the owner knows. Without this label an
   * object-access match is reported as `likely` for human review, never
   * auto-confirmed. Imported flows (HAR/OpenAPI) carry no label by design, so
   * import never auto-confirms an IDOR — a human labels it first. (§6/§9.)
   */
  ownsObject?: boolean;
  /**
   * Owner's assertion that this endpoint is a PRIVILEGED FUNCTION — one only a
   * higher-privilege role (admin, manager…) should be able to call. The oracle
   * for function-level findings (BFLA): a request names no object, so an equal
   * body under two identities could be a real privilege break OR two accounts
   * seeded alike; only the owner knows the function is privileged. With this
   * label a lower-role identity reaching it is a confirmed BFLA; without it the
   * match goes to review as `likely`. (OWASP API5:2023.)
   */
  privilegedFunction?: boolean;
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
