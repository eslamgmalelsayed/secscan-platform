/**
 * Re-test a finding after a claimed fix (Design §9, review gap 4).
 *
 * The caller re-supplies the same scan inputs (flows, identities, grant). We
 * run a fresh scan and check whether the finding's deterministic id still
 * appears; the verdict is appended to the ORIGINAL finding's retest history,
 * so a finding carries its own fixed/still-open timeline over time.
 */
import type { ScanRepo } from './repositories';
import type { ScanRequest, ScanService } from './scanService';

export interface RetestResult {
  findingId: string;
  result: 'fixed' | 'still_open';
  at: string;
  retestScanId: string;
}

export class RetestService {
  constructor(private scans: ScanRepo, private scanService: ScanService) {}

  async retest(originalScanId: string, findingId: string, req: ScanRequest): Promise<RetestResult> {
    const original = await this.scans.get(originalScanId);
    if (!original) throw new Error(`scan ${originalScanId} not found`);
    const finding = original.findings.find((f) => f.id === findingId);
    if (!finding) throw new Error(`finding ${findingId} not found in scan ${originalScanId}`);

    const fresh = await this.scanService.run(req); // its own scan record
    const stillPresent = fresh.findings.some((f) => f.id === findingId);
    const at = new Date().toISOString();
    const result: 'fixed' | 'still_open' = stillPresent ? 'still_open' : 'fixed';

    finding.retests = [...(finding.retests ?? []), { at, result }];
    if (result === 'fixed') finding.status = 'fixed';
    await this.scans.save(original);

    return { findingId, result, at, retestScanId: fresh.id };
  }
}
