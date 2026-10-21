/**
 * Renders a bilingual report for a completed scan (Design §9), reusing
 * @secscan/report. The engagement's limitations plus the scan's scope
 * refusals become the "what was not tested" section.
 */
import type { Engagement, ReportInput } from '@secscan/shared';
import { renderMarkdown, type Lang } from '@secscan/report';
import type { EngagementRepo, ScanRepo } from './repositories';

export class ReportService {
  constructor(private engagements: EngagementRepo, private scans: ScanRepo) {}

  render(engagementId: string, scanId: string, lang: Lang = 'ar'): string {
    const engagement = this.engagements.get(engagementId);
    if (!engagement) throw new Error(`engagement ${engagementId} not found`);
    const scan = this.scans.get(scanId);
    if (!scan) throw new Error(`scan ${scanId} not found`);
    const input: ReportInput = { engagement: engagement as Engagement, findings: scan.findings };
    return renderMarkdown(input, { lang, notTested: scan.notTested });
  }
}
