/**
 * Owner sign-off by email one-time code (Design §6).
 *
 * "The system owner authorizes, not the middle-man": the owner proves control
 * of a mailbox ON THE TARGET'S DOMAIN by entering a code sent there. The code
 * is stored only as an HMAC under a server secret, expires, and allows a
 * bounded number of attempts. The chain link is written by the server with
 * the server's clock, never taken from a client-supplied object.
 */
import { createHmac, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import type { Target } from '@secscan/engine';

export interface Mail { to: string; subject: string; text: string }
export interface Mailer { send(m: Mail): Promise<void> }

/** Dev mailer: prints the message to the API log. Never use outside local dev. */
export class ConsoleMailer implements Mailer {
  async send(m: Mail): Promise<void> {
    // eslint-disable-next-line no-console
    console.log(`[secscan mail] to=${m.to} subject="${m.subject}"\n${m.text}\n`);
  }
}

/** Test mailer: keeps messages in memory. */
export class MemoryMailer implements Mailer {
  readonly sent: Mail[] = [];
  async send(m: Mail): Promise<void> { this.sent.push(m); }
}

export interface OwnerChallenge {
  id: string;
  grantId: string;
  party: string;
  email: string;
  statement: string;
  codeHash: string;
  expiresAt: string;
  attempts: number;
}

export interface OwnerChallengeStore {
  put(c: OwnerChallenge): Promise<void>;
  get(id: string): Promise<OwnerChallenge | undefined>;
  delete(id: string): Promise<void>;
}

export class InMemoryOwnerChallengeStore implements OwnerChallengeStore {
  private m = new Map<string, OwnerChallenge>();
  async put(c: OwnerChallenge) { this.m.set(c.id, { ...c }); }
  async get(id: string) { const c = this.m.get(id); return c && { ...c }; }
  async delete(id: string) { this.m.delete(id); }
}

export const OTP_TTL_MS = 10 * 60_000;
export const OTP_MAX_ATTEMPTS = 5;

export function newChallengeId(): string { return randomUUID(); }
export function newCode(): string { return String(randomInt(0, 1_000_000)).padStart(6, '0'); }

export function hashCode(secret: string, challengeId: string, code: string): string {
  return createHmac('sha256', secret).update(`${challengeId}:${code}`).digest('hex');
}

export function codeMatches(secret: string, c: OwnerChallenge, code: string): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  const a = Buffer.from(hashCode(secret, c.id, code), 'hex');
  const b = Buffer.from(c.codeHash, 'hex');
  return a.length === b.length && timingSafeEqual(a, b);
}

/** The owner's mailbox must be on a target's domain: owner@example.com may
 *  sign for example.com or app.example.com, never for other.com. IP and
 *  single-label lab hosts cannot match; those use the admin manual path. */
export function emailDomainCoversTargets(email: string, targets: Target[]): boolean {
  const at = email.lastIndexOf('@');
  if (at < 0) return false;
  const domain = email.slice(at + 1).trim().toLowerCase().replace(/\.+$/, '');
  if (!domain.includes('.')) return false;
  return targets.every((t) => {
    const h = t.host.toLowerCase().replace(/\.+$/, '');
    return h === domain || h.endsWith(`.${domain}`);
  });
}

/** For audit detail: never write the full address of a third party into logs. */
export function maskEmail(email: string): string {
  const [user, domain] = email.split('@');
  return `${user.slice(0, 1)}***@${domain ?? ''}`;
}
