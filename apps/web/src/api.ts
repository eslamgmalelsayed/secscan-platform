/** Thin client for the SecScan API (proxied under /api by Vite). */
import { reactive } from 'vue';

export const settings = reactive({
  adminToken: localStorage.getItem('secscan.adminToken') ?? '',
  apiToken: localStorage.getItem('secscan.apiToken') ?? '',
  actor: localStorage.getItem('secscan.actor') ?? 'operator@local',
});
export function saveSettings() {
  localStorage.setItem('secscan.adminToken', settings.adminToken);
  localStorage.setItem('secscan.apiToken', settings.apiToken);
  localStorage.setItem('secscan.actor', settings.actor);
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method,
    headers: {
      'content-type': 'application/json',
      // Bearer token for every non-public route when API auth is configured.
      ...(settings.apiToken ? { authorization: `Bearer ${settings.apiToken}` } : {}),
      ...(settings.adminToken ? { 'x-admin-token': settings.adminToken } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? JSON.parse(text) : null;
  if (!res.ok) throw new ApiError(res.status, data?.error ?? data?.message ?? `${res.status} ${res.statusText}`);
  return data as T;
}

export interface Health {
  ok: boolean; legalResolved: boolean; adminTokenRequired: boolean;
  apiTokenRequired: boolean; ownerEmailSignOff: boolean; identities: number;
}

export const api = {
  health: () => call<Health>('GET', '/health'),
  identities: () => call<Identity[]>('GET', '/identities'),
  grants: {
    list: () => call<GrantSummary[]>('GET', '/grants'),
    get: (id: string) => call<any>('GET', `/grants/${id}`),
    create: (grant: unknown) => call<{ grantId: string }>('POST', '/grants', { grant, actor: settings.actor }),
    ownership: (id: string) => call<GrantSummary & { verification: { ok: boolean; detail: string[] } }>('POST', `/grants/${id}/ownership`, { actor: settings.actor }),
    ownershipManual: (id: string) => call<GrantSummary>('POST', `/grants/${id}/ownership/manual`, { actor: settings.actor }),
    // Owner sign-off by email OTP (two steps): request a code, then confirm it.
    ownerSignRequest: (id: string, owner: { party: string; email: string; statement: string }) =>
      call<{ challengeId: string; expiresAt: string }>('POST', `/grants/${id}/owner-sign/request`, { owner, actor: settings.actor }),
    ownerSignConfirm: (id: string, challengeId: string, code: string) =>
      call<GrantSummary>('POST', `/grants/${id}/owner-sign/confirm`, { challengeId, code, actor: settings.actor }),
    // Lab-only manual signature (admin token required).
    ownerSign: (id: string, link: unknown) => call<GrantSummary>('POST', `/grants/${id}/owner-sign`, { link, actor: settings.actor }),
    approve: (id: string) => call<GrantSummary>('POST', `/grants/${id}/approve`, { actor: settings.actor }),
    revoke: (id: string) => call<GrantSummary>('POST', `/grants/${id}/revoke`, { actor: settings.actor }),
    audit: (id: string) => call<AuditEntry[]>('GET', `/grants/${id}/audit`),
  },
  engagements: {
    list: () => call<any[]>('GET', '/engagements'),
    create: (engagement: unknown) => call<{ id: string }>('POST', '/engagements', { engagement }),
  },
  flows: {
    import: (body: unknown) => call<{ count: number; flows: Flow[] }>('POST', '/flows/import', body),
  },
  scans: {
    list: () => call<ScanSummary[]>('GET', '/scans'),
    get: (id: string) => call<ScanRecord>('GET', `/scans/${id}`),
    run: (body: unknown) => call<ScanSummary>('POST', '/scans', { ...(body as object), actor: settings.actor }),
    stop: (id: string) => call<{ id: string; stopping: boolean }>('POST', `/scans/${id}/stop`, { actor: settings.actor }),
    report: (id: string, lang: 'ar' | 'en') => call<{ markdown: string }>('GET', `/scans/${id}/report?lang=${lang}`),
    evidence: (id: string) => call<unknown>('GET', `/scans/${id}/evidence`),
  },
};

export interface Identity { role: string; tenant?: string | null; sessionRef?: string | null }
export interface Flow {
  method: string; url: string; headers?: Record<string, string>; body?: string | null;
  capturedAsRole?: string; capturedAsTenant?: string | null; requiresAuth?: boolean; ownsObject?: boolean;
}
export interface GrantSummary {
  grantId: string; status: string; ownershipVerified: boolean; adminApproved: boolean;
  targets?: { host: string; scheme: string; port: number | null }[]; ownershipProof?: string;
  notBefore?: string; notAfter?: string; allowStateChanging?: boolean; ownerSigned?: boolean;
}
export interface AuditEntry { id: string; at: string; actor: string; action: string; grantId?: string; detail?: string }
export interface ScanSummary {
  id: string; engagementId: string; grantId: string; status: string; createdAt?: string;
  confirmed: number; review: number; notTested: number; telemetry?: Record<string, number | null>;
}
export interface Finding {
  id: string; title: { ar: string; en: string }; severity: string; confidence: string;
  cvss?: { score: number; vector?: string }; asset: string; location?: string;
  description: { ar: string; en: string }; impact: { ar: string; en: string }; remediation: { ar: string; en: string };
  evidence: { kind: string; label?: string; content: string }[]; controls: { framework: string; control: string }[];
}
export interface ScanRecord extends Omit<ScanSummary, 'confirmed' | 'review' | 'notTested'> {
  findings: Finding[]; review?: Finding[]; notTested: string[];
}
