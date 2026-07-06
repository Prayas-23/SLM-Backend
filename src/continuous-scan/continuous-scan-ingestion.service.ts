import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

/**
 * CVS Ingestion Service — entry point for all scanner integrations.
 *
 * Architecture:
 *   Scanner API (Qualys / Tenable / Rapid7 / OpenVAS / Defender)
 *       → ingestFindings()
 *       → ContinuousScanFinding (status: NEW)
 *       → ContinuousScanService.assignAll() [optional auto-assign]
 *
 * Each scanner integration should call submitFinding() with its normalized data.
 * Do NOT create SecurityRequests or Vulnerabilities here — that happens in
 * ContinuousScanService.acceptFinding() only.
 */
@Injectable()
export class ContinuousScanIngestionService {
  private readonly logger = new Logger(ContinuousScanIngestionService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Submit a single normalized finding into the ingestion queue.
   * Called by future scanner integration adapters (Qualys, Tenable, Rapid7, etc.).
   *
   * @param scannerName   Identifier string e.g. "QUALYS" | "TENABLE" | "RAPID7" | "OPENVAS" | "DEFENDER"
   * @param source        Same as scannerName — retained for future sub-type routing
   * @param assetId       Optional InfrastructureAsset.id — used for auto-assign
   * @param assetName     Human-readable asset name (denormalized for display)
   * @param vulnTitle     Short vulnerability title
   * @param description   Full description (optional)
   * @param severity      CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
   * @param cvss          CVSS score 0–10 (optional)
   * @param cve           CVE identifier (optional)
   */
  async submitFinding(params: {
    scannerName: string;
    source: string;
    assetId?: string;
    assetName?: string;
    vulnTitle: string;
    description?: string;
    severity: string;
    cvss?: number;
    cve?: string;
  }) {
    this.logger.log(`[${params.scannerName}] Ingesting finding: ${params.vulnTitle}`);

    const slaDays: Record<string, number> = {
      CRITICAL: 30, HIGH: 45, MEDIUM: 90, LOW: 180, INFORMATIONAL: 365,
    };

    const now = new Date();
    const slaDue = new Date(now);
    slaDue.setDate(slaDue.getDate() + (slaDays[params.severity.toUpperCase()] ?? 90));

    return this.prisma.continuousScanFinding.create({
      data: {
        scannerName: params.scannerName,
        source: params.source,
        assetId: params.assetId,
        assetName: params.assetName,
        vulnTitle: params.vulnTitle,
        description: params.description,
        severity: params.severity as never,
        cvss: params.cvss,
        cve: params.cve,
        status: 'NEW',
        slaDueAt: slaDue,
      },
    });
  }

  /**
   * Placeholder: Future scheduled ingestion from scanner APIs.
   * Each scanner integration will implement its own fetch logic
   * and call submitFinding() for each result.
   *
   * Supported future integrations:
   *   - Qualys VMDR API
   *   - Tenable.io API
   *   - Rapid7 InsightVM API
   *   - OpenVAS GVM API
   *   - Microsoft Defender for Cloud API
   */
  async ingestFindings(scannerName?: string) {
    this.logger.log(`CVS ingestion triggered for: ${scannerName ?? 'all scanners'} (not yet implemented)`);
    // Future: scanner-specific fetch logic goes here
  }
}
