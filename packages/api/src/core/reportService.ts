/**
 * Renders a bilingual report for a completed scan (Design §9), reusing
 * @secscan/report. The engagement's limitations plus the scan's scope
 * refusals become the "what was not tested" section.
 */
import type { Engagement, Finding, ReportInput } from '@secscan/shared';
import { renderMarkdown, type Lang } from '@secscan/report';
import type { EngagementRepo, ScanRepo } from './repositories';

/** Machine-readable evidence pack delivered next to the Markdown (Design §9,
 *  review gap 7): everything a reviewer or an auditor needs, with each
 *  finding's full evidence and the grant fingerprint it was produced under. */
export interface EvidenceBundle {
  generatedAt: string;
  engagement: Engagement;
  scan: { id: string; status: string; createdAt: string; telemetry?: Record<string, number | null> };
  findings: Finding[];      // confirmed (report-ready)
  review: Finding[];        // below the bar, for human review
  notTested: string[];
}

export class ReportService {
  constructor(private engagements: EngagementRepo, private scans: ScanRepo) {}

  async render(engagementId: string, scanId: string, lang: Lang = 'ar'): Promise<string> {
    const engagement = await this.engagements.get(engagementId);
    if (!engagement) throw new Error(`engagement ${engagementId} not found`);
    const scan = await this.scans.get(scanId);
    if (!scan) throw new Error(`scan ${scanId} not found`);
    const input: ReportInput = { engagement: engagement as Engagement, findings: [...scan.findings, ...(scan.review ?? [])] };
    return renderMarkdown(input, { lang, notTested: scan.notTested });
  }

  async bundle(engagementId: string, scanId: string): Promise<EvidenceBundle> {
    const engagement = await this.engagements.get(engagementId);
    if (!engagement) throw new Error(`engagement ${engagementId} not found`);
    const scan = await this.scans.get(scanId);
    if (!scan) throw new Error(`scan ${scanId} not found`);
    return {
      generatedAt: new Date().toISOString(),
      engagement: engagement as Engagement,
      scan: { id: scan.id, status: scan.status, createdAt: scan.createdAt, telemetry: scan.telemetry },
      findings: scan.findings,
      review: scan.review ?? [],
      notTested: scan.notTested,
    };
  }
}
