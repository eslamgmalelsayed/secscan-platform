/**
 * Per-identity authentication material, held out of findings and logs (§7).
 * A test identity is paired with an opaque `sessionRef`; the secrets live here
 * keyed by that handle and are applied to outgoing requests by the sender.
 */
export interface SessionMaterial {
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  bearer?: string;
}

export class SecretStore {
  private byRef = new Map<string, SessionMaterial>();

  put(sessionRef: string, material: SessionMaterial): void {
    this.byRef.set(sessionRef, material);
  }

  /** Anonymous (no ref) gets empty material. */
  material(sessionRef: string | null | undefined): SessionMaterial {
    if (!sessionRef) return {};
    return this.byRef.get(sessionRef) ?? {};
  }

  has(sessionRef: string): boolean {
    return this.byRef.has(sessionRef);
  }
}

export function cookieHeader(cookies: Record<string, string> = {}): string {
  return Object.entries(cookies).map(([k, v]) => `${k}=${v}`).join('; ');
}
