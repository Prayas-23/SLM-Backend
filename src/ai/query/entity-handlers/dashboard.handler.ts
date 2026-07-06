import { PrismaService } from '../../../prisma/prisma.service';
import { Environment, Severity, VulnerabilityStatus } from '@prisma/client';

/**
 * DashboardHandler
 *
 * Returns structured KPI data only.
 * No LLM text generation. No executive summaries.
 * Output is a single structured JSON record for Phase 2.3 Prompt Builder.
 */
export class DashboardHandler {
  constructor(private readonly prisma: PrismaService) {}

  async summary(environment?: string) {
    const envFilter = environment && Object.values(Environment).includes(environment as Environment)
      ? { environment: environment as Environment }
      : {};

    const vulnWhere = { ...envFilter, deletedAt: null };
    const appWhere  = { ...envFilter, deletedAt: null, isActive: true };

    const [
      totalVulns,
      criticalVulns,
      highVulns,
      openVulns,
      slaBreached,
      totalApps,
      totalRequests,
      criticalCvs,
    ] = await Promise.all([
      this.prisma.vulnerability.count({ where: vulnWhere }),
      this.prisma.vulnerability.count({ where: { ...vulnWhere, severity: Severity.CRITICAL } }),
      this.prisma.vulnerability.count({ where: { ...vulnWhere, severity: Severity.HIGH } }),
      this.prisma.vulnerability.count({ where: { ...vulnWhere, status: VulnerabilityStatus.OPEN } }),
      this.prisma.slaTracking.count({ where: { isBreached: true } }),
      this.prisma.application.count({ where: appWhere }),
      this.prisma.securityRequest.count({ where: { deletedAt: null } }),
      this.prisma.continuousScanFinding.count({ where: { severity: Severity.CRITICAL, status: { not: 'PATCHED' } } }),
    ]);

    return {
      data: [{
        totalVulnerabilities: totalVulns,
        critical:             criticalVulns,
        high:                 highVulns,
        open:                 openVulns,
        slaBreached,
        totalApplications:    totalApps,
        totalSecurityRequests: totalRequests,
        criticalCvsFindings:  criticalCvs,
        environment:          environment ?? 'ALL',
      }],
      total: 1,
    };
  }

  async analyze(environment?: string) {
    return this.summary(environment);
  }
}
