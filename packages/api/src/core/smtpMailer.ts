/**
 * SMTP delivery for owner sign-off codes. Locally this points at Mailpit
 * (docker-compose: SMTP on 127.0.0.1:1025, inbox UI on http://127.0.0.1:8025).
 * In any shared deployment, point SECSCAN_SMTP_URL at a real relay over TLS.
 */
import nodemailer, { type Transporter } from 'nodemailer';
import type { Mail, Mailer } from './ownerSignature';

export class SmtpMailer implements Mailer {
  private transport: Transporter;
  constructor(smtpUrl: string, private from: string) {
    this.transport = nodemailer.createTransport(smtpUrl);
  }
  async send(m: Mail): Promise<void> {
    await this.transport.sendMail({ from: this.from, to: m.to, subject: m.subject, text: m.text });
  }
}
