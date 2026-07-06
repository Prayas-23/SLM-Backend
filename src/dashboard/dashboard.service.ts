import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SlaMetricsService } from '../sla/sla-metrics.service';
import {
  Environment,
  Severity,
  VulnerabilityStatus,
  CloudProvider,
  CloudResourceType,
  Prisma,
} from '@prisma/client';
import {
  DashboardFilterDto,
  OverviewMetrics,
  VulnerabilityDashboard,
  SecurityRequestDashboard,
  SlaDashboard,
  ApplicationDashboard,
  InfrastructureDashboard,
  CloudDashboard,
  AppVulnCount,
  AppSlaCompliance,
  InfraVulnCount,
  InfraSlaCompliance,
  CommonVulnerabilitiesDashboard,
  HealthScorecardsDashboard,
  OwnerPerformanceDashboard,
  VaptScheduleDashboard,
  BiaRiskMetrics,
  TopPatchingVulnerabilitiesDashboard,
  TopCodingVulnerabilitiesDashboard,
  DataClassificationRiskDashboard,
  BiaApplicationAssetRiskDashboard,
  NewVsRecurringDashboard,
  NewVsRecurringTrendPoint,
  RepetitionPatternsDashboard,
  RepetitionPatternDto,
  SecurityControlComplianceDto,
  SecurityControlsComplianceDashboard,
} from './dashboard.dto';


// ── Active SLA statuses (same set as SlaMetricsService) ──────────────────────
const ACTIVE_SLA_STATUSES: VulnerabilityStatus[] = [
  VulnerabilityStatus.OPEN,
  VulnerabilityStatus.ASSIGNED,
  VulnerabilityStatus.IN_PROGRESS,
  VulnerabilityStatus.PATCHED,
  VulnerabilityStatus.PENDING_REVALIDATION,
];

@Injectable()
export class DashboardService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly slaMetrics: SlaMetricsService,
  ) { }

  // ── Internal Helpers ────────────────────────────────────────────────────────

  /**
   * Builds a shared Prisma `where` object for vulnerability queries
   * using the standard Sentinel filter (environment + date range).
   */
  private buildVulnWhere(filter: DashboardFilterDto, extra: Prisma.VulnerabilityWhereInput = {}): Prisma.VulnerabilityWhereInput {
    const where: Prisma.VulnerabilityWhereInput = { deletedAt: null, ...extra };
    if (filter.environment) where.environment = filter.environment as Environment;
    if (filter.startDate || filter.endDate) {
      where.createdAt = {
        ...(filter.startDate && { gte: new Date(filter.startDate) }),
        ...(filter.endDate && { lte: new Date(filter.endDate) }),
      };
    }
    return where;
  }

  /**
   * Builds a shared Prisma `where` object for security request queries.
   */
  private buildRequestWhere(filter: DashboardFilterDto, extra: Prisma.SecurityRequestWhereInput = {}): Prisma.SecurityRequestWhereInput {
    const where: Prisma.SecurityRequestWhereInput = { deletedAt: null, ...extra };
    if (filter.environment) where.environment = filter.environment as Environment;
    if (filter.startDate || filter.endDate) {
      where.initiatedOn = {
        ...(filter.startDate && { gte: new Date(filter.startDate) }),
        ...(filter.endDate && { lte: new Date(filter.endDate) }),
      };
    }
    return where;
  }

  // ── Overview ────────────────────────────────────────────────────────────────

  async getOverview(filter: DashboardFilterDto): Promise<OverviewMetrics> {
    const vulnWhere = this.buildVulnWhere(filter);
    const reqWhere = this.buildRequestWhere(filter);
    const now = new Date();

    const [
      totalApplications,
      totalInfrastructureAssets,
      totalCloudResources,
      totalSecurityRequests,
      totalVulnerabilities,
      openVulnerabilities,
      closedVulnerabilities,
      activeSlaTotal,
      activeSlaCompliant,
      openCvsFindings,
    ] = await this.prisma.$transaction([
      // Applications, infra, cloud are not filtered by env/date for overview counts
      this.prisma.application.count({ where: { deletedAt: null } }),
      this.prisma.infrastructureAsset.count({ where: { deletedAt: null } }),
      this.prisma.cloudResource.count({ where: { deletedAt: null } }),
      this.prisma.securityRequest.count({ where: reqWhere }),
      this.prisma.vulnerability.count({ where: vulnWhere }),
      this.prisma.vulnerability.count({
        where: { ...vulnWhere, status: { not: VulnerabilityStatus.CLOSED } },
      }),
      this.prisma.vulnerability.count({
        where: { ...vulnWhere, status: VulnerabilityStatus.CLOSED },
      }),
      // SLA compliance: active statuses only
      this.prisma.vulnerability.count({
        where: { ...vulnWhere, status: { not: VulnerabilityStatus.CLOSED } },
      }),
      this.prisma.vulnerability.count({
        where: { ...vulnWhere, status: { not: VulnerabilityStatus.CLOSED }, slaDueDate: { gt: now } },
      }),
      this.prisma.continuousScanFinding.count({
        where: { status: { not: 'PATCHED' } }
      }),
    ]);

    const slaCompliancePercentage =
      activeSlaTotal > 0
        ? Math.round((activeSlaCompliant / activeSlaTotal) * 100)
        : 100;

    return {
      totalApplications,
      totalInfrastructureAssets,
      totalCloudResources,
      totalSecurityRequests,
      totalVulnerabilities,
      openVulnerabilities,
      closedVulnerabilities,
      slaCompliancePercentage,
      openCvsFindings,
    };
  }

  // ── Vulnerability Dashboard ─────────────────────────────────────────────────

  async getVulnerabilityDashboard(filter: DashboardFilterDto): Promise<VulnerabilityDashboard> {
    const where = this.buildVulnWhere(filter, { status: { not: VulnerabilityStatus.CLOSED } });

    // Group by severity
    const severityGroups = await this.prisma.vulnerability.groupBy({
      by: ['severity'],
      where,
      _count: { _all: true },
    });

    // Group by status
    const statusGroups = await this.prisma.vulnerability.groupBy({
      by: ['status'],
      where,
      _count: { _all: true },
    });

    // Group by source
    const sourceGroups = await this.prisma.vulnerability.groupBy({
      by: ['source'],
      where,
      _count: { _all: true },
    });

    // Build full severity breakdown including zero counts
    const severityMap = new Map(severityGroups.map((g) => [g.severity, g._count._all]));
    const severityBreakdown = Object.values(Severity).map((sev) => ({
      severity: sev,
      count: severityMap.get(sev) ?? 0,
    }));

    // Build full status breakdown
    const statusMap = new Map(statusGroups.map((g) => [g.status, g._count._all]));
    const statusBreakdown = Object.values(VulnerabilityStatus)
      .filter((st) => st !== VulnerabilityStatus.CLOSED)
      .map((st) => ({
        status: st,
        count: statusMap.get(st) ?? 0,
      }));

    // Source breakdown (dynamic — only existing sources)
    const sourceBreakdown = sourceGroups.map((g) => ({
      source: g.source,
      count: g._count._all,
    }));

    return { severityBreakdown, statusBreakdown, sourceBreakdown };
  }

  // ── Security Request Dashboard ──────────────────────────────────────────────

  async getSecurityRequestDashboard(filter: DashboardFilterDto): Promise<SecurityRequestDashboard> {
    const where = this.buildRequestWhere(filter);

    const [sourceGroups, statusGroups, openRequests, closedRequests] =
      await this.prisma.$transaction([
        (this.prisma.securityRequest as unknown as { groupBy: Function }).groupBy({
          by: ['source'],
          where,
          _count: { _all: true },
        }),
        (this.prisma.securityRequest as unknown as { groupBy: Function }).groupBy({
          by: ['status'],
          where,
          _count: { _all: true },
        }),
        this.prisma.securityRequest.count({
          where: { ...where, status: 'OPEN' as never },
        }),
        this.prisma.securityRequest.count({
          where: { ...where, status: 'CLOSED' as never },
        }),
      ]);

    return {
      requestCountBySource: sourceGroups.map((g) => ({
        source: g.source,
        count: g._count._all,
      })),
      requestCountByStatus: statusGroups.map((g) => ({
        status: g.status,
        count: g._count._all,
      })),
      openRequests,
      closedRequests,
    };
  }

  // ── SLA Dashboard ───────────────────────────────────────────────────────────

  async getSlaDashboard(filter: DashboardFilterDto): Promise<SlaDashboard> {
    // Reuse Phase 2F SlaMetricsService for the core summary
    const [summary, bySeverity, byEnvironment] = await Promise.all([
      this.slaMetrics.getSummary(filter),
      this.slaMetrics.getBySeverity(filter),
      this.slaMetrics.getByEnvironment(filter),
    ]);

    return {
      total: summary.total,
      withinSla: summary.withinSla,
      breached: summary.breached,
      critBreached: summary.critBreached,
      highBreached: summary.highBreached,
      compliancePct: summary.compliancePct,
      complianceBySeverity: bySeverity,
      complianceByEnvironment: byEnvironment,
    };
  }

  // ── Application Dashboard ───────────────────────────────────────────────────

  async getApplicationDashboard(filter: DashboardFilterDto): Promise<ApplicationDashboard> {
    const vulnWhere = this.buildVulnWhere(filter, { status: { not: VulnerabilityStatus.CLOSED } });
    const now = new Date();

    // Fetch all applications
    const applications = await this.prisma.application.findMany({
      where: { deletedAt: null },
      select: { id: true, name: true },
    });

    // ── Vulnerability counts per application ─────────────────────────────────────────
    // Previously: grouped vulns by requestId, then fetched each request
    // to resolve the targetAppId. Still the same two-query approach but
    // unchanged here — the N+1 was in the SLA loop below.

    const vulnCountsRaw = await this.prisma.vulnerability.groupBy({
      by: ['requestId'],
      where: vulnWhere,
      _count: { _all: true },
    });

    const requests = await this.prisma.securityRequest.findMany({
      where: {
        deletedAt: null,
        id: { in: vulnCountsRaw.map((v) => v.requestId) },
      },
      select: { id: true, targetAppId: true },
    });
    const requestToApp = new Map(requests.map((r) => [r.id, r.targetAppId]));

    const appVulnMap = new Map<string, number>();
    for (const row of vulnCountsRaw) {
      const appId = requestToApp.get(row.requestId);
      if (appId) {
        appVulnMap.set(appId, (appVulnMap.get(appId) ?? 0) + row._count._all);
      }
    }

    const applicationVulnerabilityCounts: AppVulnCount[] = applications.map((app) => ({
      applicationId: app.id,
      applicationName: app.name,
      vulnerabilityCount: appVulnMap.get(app.id) ?? 0,
    }));

    const topVulnerableApplications = [...applicationVulnerabilityCounts]
      .sort((a, b) => b.vulnerabilityCount - a.vulnerabilityCount)
      .slice(0, 10);

    // ── SLA compliance per application — OPTIMIZED ────────────────────────────────
    //
    // BEFORE: Promise.all(N × $transaction([count, count]))
    //   = 2N SQL statements (1 pair per application)
    //
    // AFTER: 2 grouped queries covering all applications at once
    //   = 2 SQL statements (fixed cost, independent of app count)
    //
    // Strategy:
    //   Query 1 — groupBy requestId, status: gives total active vulns per req.
    //   Query 2 — groupBy requestId, slaDueDate > now: gives compliant count.
    //   Resolve requestId → appId via the requestToApp map built above.
    //   Aggregate into per-app totals + compliant counts in O(M) Node.js.

    const allRequestIds = requests.map((r) => r.id);

    const baseSlaWhere: Prisma.VulnerabilityWhereInput = {
      ...vulnWhere,
      status: { not: VulnerabilityStatus.CLOSED },
      requestId: { in: allRequestIds },
    };

    const [slaGroupsTotal, slaGroupsCompliant] = await this.prisma.$transaction([
      // Total active vulns per requestId
      (this.prisma.vulnerability as unknown as { groupBy: Function }).groupBy({
        by: ['requestId'],
        where: baseSlaWhere,
        _count: { _all: true },
      }),
      // Compliant (within SLA due date) vulns per requestId
      (this.prisma.vulnerability as unknown as { groupBy: Function }).groupBy({
        by: ['requestId'],
        where: { ...baseSlaWhere, slaDueDate: { gt: now } },
        _count: { _all: true },
      }),
    ]) as [Array<{ requestId: string; _count: { _all: number } }>, Array<{ requestId: string; _count: { _all: number } }>];

    // Build per-app aggregates from the grouped results
    const appSlaTotal     = new Map<string, number>();
    const appSlaCompliant = new Map<string, number>();

    for (const row of slaGroupsTotal) {
      const appId = requestToApp.get(row.requestId);
      if (appId) appSlaTotal.set(appId, (appSlaTotal.get(appId) ?? 0) + row._count._all);
    }
    for (const row of slaGroupsCompliant) {
      const appId = requestToApp.get(row.requestId);
      if (appId) appSlaCompliant.set(appId, (appSlaCompliant.get(appId) ?? 0) + row._count._all);
    }

    const applicationSlaCompliance: AppSlaCompliance[] = applications.map((app) => {
      const total     = appSlaTotal.get(app.id) ?? 0;
      const compliant = appSlaCompliant.get(app.id) ?? 0;
      const breached  = total - compliant;
      const compliancePct = total > 0 ? Math.round((compliant / total) * 100) : 100;
      return {
        applicationId: app.id,
        applicationName: app.name,
        total,
        compliant,
        breached,
        compliancePct,
      };
    });

    return {
      topVulnerableApplications,
      applicationVulnerabilityCounts,
      applicationSlaCompliance,
    };
  }

  // ── Infrastructure Dashboard ────────────────────────────────────────────────

  async getInfrastructureDashboard(filter: DashboardFilterDto): Promise<InfrastructureDashboard> {
    const vulnWhere = this.buildVulnWhere(filter, { status: { not: VulnerabilityStatus.CLOSED } });
    const now = new Date();

    const assets = await this.prisma.infrastructureAsset.findMany({
      where: { deletedAt: null },
      select: { id: true, serverName: true },
    });

    // Vulnerability counts via securityRequest.infrastructureAssetId
    const vulnCountsRaw = await this.prisma.vulnerability.groupBy({
      by: ['requestId'],
      where: vulnWhere,
      _count: { _all: true },
    });

    const requests = await this.prisma.securityRequest.findMany({
      where: {
        deletedAt: null,
        id: { in: vulnCountsRaw.map((v) => v.requestId) },
      },
      select: { id: true, targetInfraId: true },
    });
    const requestToAsset = new Map(requests.map((r) => [r.id, r.targetInfraId]));

    const assetVulnMap = new Map<string, number>();
    for (const row of vulnCountsRaw) {
      const assetId = requestToAsset.get(row.requestId);
      if (assetId) {
        assetVulnMap.set(assetId, (assetVulnMap.get(assetId) ?? 0) + row._count._all);
      }
    }

    const infrastructureVulnerabilityCounts: InfraVulnCount[] = assets.map((asset) => ({
      assetId: asset.id,
      assetName: asset.serverName,
      vulnerabilityCount: assetVulnMap.get(asset.id) ?? 0,
    }));

    const topVulnerableAssets = [...infrastructureVulnerabilityCounts]
      .sort((a, b) => b.vulnerabilityCount - a.vulnerabilityCount)
      .slice(0, 10);

    // SLA compliance per asset
    const infrastructureSlaCompliance: InfraSlaCompliance[] = await Promise.all(
      assets.map(async (asset) => {
        const assetReqIds = requests
          .filter((r) => r.targetInfraId === asset.id)
          .map((r) => r.id);

        const slaWhere = {
          ...vulnWhere,
          status: { not: VulnerabilityStatus.CLOSED },
          requestId: { in: assetReqIds },
        };

        const [total, compliant] = await this.prisma.$transaction([
          this.prisma.vulnerability.count({ where: slaWhere }),
          this.prisma.vulnerability.count({
            where: { ...slaWhere, slaDueDate: { gt: now } },
          }),
        ]);
        const breached = total - compliant;
        const compliancePct = total > 0 ? Math.round((compliant / total) * 100) : 100;
        return {
          assetId: asset.id,
          assetName: asset.serverName,
          total,
          compliant,
          breached,
          compliancePct,
        };
      }),
    );

    return {
      topVulnerableAssets,
      infrastructureVulnerabilityCounts,
      infrastructureSlaCompliance,
    };
  }

  // ── Cloud Dashboard ─────────────────────────────────────────────────────────

  async getCloudDashboard(filter: DashboardFilterDto): Promise<CloudDashboard> {
    const where: Prisma.CloudResourceWhereInput = { deletedAt: null };
    // Cloud resources are not scoped by env/date in the same sense —
    // but we apply environment if the schema field exists
    if (filter.environment) where.environment = filter.environment as Environment;

    const [providerGroups, typeGroups] = await this.prisma.$transaction([
      (this.prisma.cloudResource as unknown as { groupBy: Function }).groupBy({
        by: ['provider'],
        where,
        _count: { _all: true },
      }),
      (this.prisma.cloudResource as unknown as { groupBy: Function }).groupBy({
        by: ['type'],
        where,
        _count: { _all: true },
      }),
    ]);

    // Full provider breakdown including zero-count providers
    const providerMap = new Map<CloudProvider, number>(
      providerGroups.map((g: any) => [
        g.provider,
        Number(g._count._all),
      ]),
    );

    const cloudResourcesByProvider = Object.values(CloudProvider).map((p) => ({
      provider: p,
      count: Number(providerMap.get(p) ?? 0),
    }));

    // Full type breakdown including zero-count types
    const typeMap = new Map<CloudResourceType, number>(
      typeGroups.map((g: any) => [
        g.type,
        Number(g._count._all),
      ]),
    );

    const cloudResourcesByType = Object.values(CloudResourceType).map((t) => ({
      type: t,
      count: Number(typeMap.get(t) ?? 0),
    }));

    return { cloudResourcesByProvider, cloudResourcesByType };
  }

  // ── Common Vulnerabilities ──────────────────────────────────────────────────

  async getCommonVulnerabilitiesDashboard(filter: DashboardFilterDto): Promise<CommonVulnerabilitiesDashboard> {
    const where = this.buildVulnWhere(filter, { status: { not: VulnerabilityStatus.CLOSED } });
    const groups = await this.prisma.vulnerability.groupBy({
      by: ['type', 'severity', 'source'],
      where,
      _count: { _all: true },
      orderBy: { _count: { type: 'desc' } },
      take: 20, // get top 20
    });

    return {
      commonVulnerabilities: groups.map(g => ({
        type: g.type,
        severity: g.severity,
        source: g.source,
        count: g._count._all,
      })),
    };
  }

  // ── Health Scorecards ───────────────────────────────────────────────────────

  async getHealthScorecardsDashboard(filter: DashboardFilterDto): Promise<HealthScorecardsDashboard> {
    // Only fetch applications. The logic filters for deletedAt: null
    const applications = await this.prisma.application.findMany({
      where: { deletedAt: null },
      include: {
        owner: { select: { name: true } },
        securityRequests: {
          where: { deletedAt: null },
          include: {
            vulnerabilities: {
              where: { deletedAt: null },
              select: { id: true, severity: true, status: true, slaDueDate: true },
            },
          },
        },
      },
    });

    const now = new Date();
    
    const scorecards = applications.map(app => {
      // Calculate patch compliance as a proxy from SLA compliance if patching rate isn't available
      // or we just use slaCompliancePct if we don't have separate patching data.
      // The prompt formula was using slaCompliancePct.
      const allVulns = app.securityRequests?.flatMap((req: any) => req.vulnerabilities) || [];
      const totalVulns = allVulns.length;
      const closedVulnCount = allVulns.filter((v: any) => v.status === 'CLOSED').length;
      
      const openVulnCount = totalVulns - closedVulnCount;
      const critVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
      
      const vulnsWithSla = allVulns.filter((v: any) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v: any) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
      
      // Calculate patch compliance independently based on overall closure rate
      const patchCompliancePct = totalVulns > 0 ? Math.round((closedVulnCount / totalVulns) * 100) : 100;
      
      const isVaptOverdue = app.nextVaptDate && app.nextVaptDate < now;
      
      let score = 50 + (slaCompliancePct * 0.5) - (critVulnCount * 5) - ((openVulnCount - critVulnCount) * 1);
      if (isVaptOverdue) score -= 10;
      
      // Clamp between 0 and 100
      score = Math.max(0, Math.min(100, Math.round(score)));
      
      let healthStatus: 'Healthy' | 'At Risk' | 'Critical' = 'Healthy';
      if (score < 50) healthStatus = 'Critical';
      else if (score < 75) healthStatus = 'At Risk';

      return {
        applicationId: app.id,
        applicationName: app.name,
        ownerName: app.owner?.name ?? null,
        score,
        slaCompliancePct: Math.round(slaCompliancePct),
        patchCompliancePct,
        lastVaptDate: app.lastVaptDate,
        nextVaptDate: app.nextVaptDate,
        healthStatus,
      };
    });

    // Sort ascending: Display the most vulnerable (lowest score) applications at the top
    return { scorecards: scorecards.sort((a, b) => a.score - b.score) };
  }

  // ── Owner Performance ───────────────────────────────────────────────────────

  async getOwnerPerformanceDashboard(filter: DashboardFilterDto): Promise<OwnerPerformanceDashboard> {
    const where = this.buildVulnWhere(filter);

    // Group assigned vulnerabilities by owner + status (unchanged — already efficient)
    const groupedVulns = await this.prisma.vulnerability.groupBy({
      by: ['assignedToId', 'status'],
      where: {
        ...where,
        assignedToId: { not: null },
      },
      _count: { _all: true },
    });

    // ── SLA breach count per owner — OPTIMIZED ────────────────────────────────────────────
    //
    // BEFORE: findMany(all breach rows, select assignedToId)
    //   Loads every breached vulnerability row into Node.js memory.
    //   At scale this could be thousands of rows.
    //   Then reduces to a count map in JavaScript.
    //
    // AFTER: groupBy(assignedToId) with breach filter
    //   PostgreSQL produces one row per owner containing the count.
    //   Zero rows loaded into Node.js beyond the tiny summary.
    //
    const slaBreachGroups = await this.prisma.vulnerability.groupBy({
      by: ['assignedToId'],
      where: {
        ...where,
        assignedToId: { not: null },
        status: { not: VulnerabilityStatus.CLOSED },
        slaTracking: { isBreached: true },
      },
      _count: { _all: true },
    });

    // Convert to O(1) lookup map (same shape as before — no response change)
    const slaBreachCountByOwner: Record<string, number> = {};
    for (const row of slaBreachGroups) {
      if (row.assignedToId) {
        slaBreachCountByOwner[row.assignedToId] = row._count._all;
      }
    }

    const ownerStats = new Map<string, { assigned: number; closed: number }>();

    for (const group of groupedVulns) {
      const ownerId = group.assignedToId!;
      const isClosed = group.status === VulnerabilityStatus.CLOSED || group.status === VulnerabilityStatus.PATCHED;

      if (!ownerStats.has(ownerId)) {
        ownerStats.set(ownerId, { assigned: 0, closed: 0 });
      }

      const stats = ownerStats.get(ownerId)!;
      stats.assigned += group._count._all;
      if (isClosed) {
        stats.closed += group._count._all;
      }
    }

    const userIds = Array.from(ownerStats.keys());
    const users = await this.prisma.user.findMany({
      where: { id: { in: userIds } },
      select: { id: true, name: true, role: true },
    });

    const ownerPerformances = users.map(user => {
      const stats = ownerStats.get(user.id)!;
      const slaBreaches = slaBreachCountByOwner[user.id] || 0;

      const closurePercentage = stats.assigned > 0 ? Math.round((stats.closed / stats.assigned) * 100) : 100;
      const breachRate = stats.assigned > 0 ? Math.round((slaBreaches / stats.assigned) * 100) : 0;

      let grade: 'A' | 'B' | 'C' | 'D' = 'A';
      if (breachRate > 50) grade = 'D';
      else if (breachRate > 20) grade = 'C';
      else if (breachRate > 5) grade = 'B';

      return {
        ownerId: user.id,
        ownerName: user.name,
        role: user.role,
        assignedFindings: stats.assigned,
        patchedOnTime: stats.closed,
        closedFindings: stats.closed,
        slaBreaches,
        closurePercentage,
        breachRate,
        grade,
      };
    });

    return { ownerPerformances };
  }

  // ── VAPT Schedule ───────────────────────────────────────────────────────────

  async getVaptScheduleDashboard(): Promise<VaptScheduleDashboard> {
    const applications = await this.prisma.application.findMany({
      where: { deletedAt: null, vaptStatus: { not: null } },
      include: { owner: { select: { name: true } } }
    });

    // Infrastructure assets technically don't have nextVaptDate in the schema right now, 
    // but the dashboard mocks included "Infra". 
    // We will stick to Application for now as per the schema, since vaptStatus/nextVaptDate are on Application.

    const now = new Date();
    
    const schedule = applications.map(app => {
      let overdueDays: number | null = null;
      if (app.nextVaptDate && app.nextVaptDate < now) {
        overdueDays = Math.floor((now.getTime() - app.nextVaptDate.getTime()) / (1000 * 60 * 60 * 24));
      }
      
      // Determine initials from ownerName
      const ownerName = app.owner?.name ?? 'Unknown';
      const initials = ownerName.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();

      return {
        assetId: app.id,
        assetName: app.name,
        assetType: 'Application' as const,
        vaptStatus: app.vaptStatus || 'Scheduled',
        dueDate: app.nextVaptDate,
        overdueDays,
        ownerInitials: initials,
      };
    });

    return { schedule: schedule.sort((a, b) => {
       const dateA = a.dueDate ? a.dueDate.getTime() : Infinity;
       const dateB = b.dueDate ? b.dueDate.getTime() : Infinity;
       return dateA - dateB;
    }) };
  }

  // ── BIA Risk Metrics ────────────────────────────────────────────────────────

  /**
   * Returns three BIA risk KPI counts.
   *
   * "BIA" = criticality field equals 'Critical' on the Application or
   * InfrastructureAsset record. We use Prisma relational filters (some) to
   * find BIA assets that contain qualifying vulnerabilities in a single
   * database round-trip per metric — avoiding the N+1 pattern.
   *
   * SLA breach definition: vulnerability is active (ACTIVE_SLA_STATUSES) and
   * its slaDueDate has passed (< now), matching the same logic used throughout
   * this service.
   */
  async getBiaRiskMetrics(filter: DashboardFilterDto): Promise<BiaRiskMetrics> {
    const now = new Date();
    const vulnWhere = this.buildVulnWhere(filter);

    // Shared vulnerability filter: open CRITICAL or HIGH severity
    const critHighVulnFilter = {
      ...vulnWhere,
      severity: { in: [Severity.CRITICAL, Severity.HIGH] },
      status: { not: VulnerabilityStatus.CLOSED },
    };

    // Shared SLA breach vulnerability filter: active + past due
    const slaBreachedVulnFilter = {
      ...vulnWhere,
      status: { not: VulnerabilityStatus.CLOSED },
      slaDueDate: { lt: now },
    };

    const [
      biaAppsCritical,
      biaInfraCritical,
      biaAppsBreached,
      biaInfraBreached,
    ] = await this.prisma.$transaction([

      // BIA Apps with ≥1 CRITICAL/HIGH open vulnerability
      this.prisma.application.count({
        where: {
          deletedAt: null,
          criticality: 'Critical',
          securityRequests: {
            some: {
              deletedAt: null,
              vulnerabilities: { some: critHighVulnFilter },
            },
          },
        },
      }),

      // BIA Infra Assets with ≥1 CRITICAL/HIGH open vulnerability
      this.prisma.infrastructureAsset.count({
        where: {
          deletedAt: null,
          criticality: 'Critical',
          securityRequests: {
            some: {
              deletedAt: null,
              vulnerabilities: { some: critHighVulnFilter },
            },
          },
        },
      }),

      // BIA Apps with ≥1 active SLA breach
      this.prisma.application.count({
        where: {
          deletedAt: null,
          criticality: 'Critical',
          securityRequests: {
            some: {
              deletedAt: null,
              vulnerabilities: { some: slaBreachedVulnFilter },
            },
          },
        },
      }),

      // BIA Infra Assets with ≥1 active SLA breach
      this.prisma.infrastructureAsset.count({
        where: {
          deletedAt: null,
          criticality: 'Critical',
          securityRequests: {
            some: {
              deletedAt: null,
              vulnerabilities: { some: slaBreachedVulnFilter },
            },
          },
        },
      }),
    ]);

    return {
      biaAppsCritical,
      biaInfraCritical,
      biaAssetsBreached: biaAppsBreached + biaInfraBreached,
    };
  }

  // ── Top Patching Vulnerabilities ────────────────────────────────────────────

  /**
   * Returns the Top 10 infrastructure / OS / middleware patching vulnerabilities.
   *
   * Classification strategy:
   *   The Vulnerability.type field stores a free-text category entered during
   *   finding creation (e.g. "OS", "Middleware", "Container", "Package", etc.).
   *   We EXCLUDE well-known application-code type keywords to keep this list
   *   focused on patchable infrastructure issues.
   *
   * Aggregation strategy:
   *   1. Filter by the dashboard's environment + date range (buildVulnWhere).
   *   2. Exclude code-level vulnerability type keywords using NOT mode filters.
   *   3. groupBy type — entire aggregation runs in PostgreSQL, zero N+1.
   *   4. Resolve highest severity per group in Node.js on the small result set
   *      (Prisma groupBy does not support a MAX on enum fields directly).
   *   5. Sort: CRITICAL > HIGH > MEDIUM > LOW > INFORMATIONAL, then by count.
   *   6. Return Top 10.
   */
  async getTopPatchingVulnerabilities(
    filter: DashboardFilterDto,
  ): Promise<TopPatchingVulnerabilitiesDashboard> {
    // Severity ordering for sort (higher index = higher priority)
    const SEV_ORDER: Record<string, number> = {
      CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1,
    };

    // Keywords that identify code-level (non-patching) vulnerability types.
    // Any vuln whose `type` contains one of these strings (case-insensitive)
    // is excluded from this endpoint.
    const CODE_LEVEL_KEYWORDS = [
      'injection',
      'xss',
      'cross-site',
      'csrf',
      'xxe',
      'authentication',
      'authoriz',
      'secret',
      'hardcoded',
      'business logic',
      'logic flaw',
      'insecure direct',
      'idor',
      'sast',
      'code review',
      'race condition',
      'deserialization',
    ];

    const baseWhere = this.buildVulnWhere(filter);

    // Build Prisma AND-NOT filters to exclude code-level types
    const excludeFilters: Prisma.VulnerabilityWhereInput[] = CODE_LEVEL_KEYWORDS.map(
      (kw) => ({
        NOT: { type: { contains: kw, mode: 'insensitive' as Prisma.QueryMode } },
      }),
    );

    const where: Prisma.VulnerabilityWhereInput = {
      ...baseWhere,
      AND: excludeFilters,
    };

    // Single grouped query — PostgreSQL aggregates count per type
    const groups = await this.prisma.vulnerability.groupBy({
      by: ['type', 'severity'],
      where,
      _count: { _all: true },
    });

    // Merge groups with the same type, keeping the highest severity
    const typeMap = new Map<string, { severity: string; count: number }>();
    for (const row of groups) {
      const existing = typeMap.get(row.type);
      if (!existing) {
        typeMap.set(row.type, { severity: row.severity, count: row._count._all });
      } else {
        // Accumulate count across severity sub-groups for the same type
        existing.count += row._count._all;
        // Promote to higher severity if found
        if ((SEV_ORDER[row.severity] ?? 0) > (SEV_ORDER[existing.severity] ?? 0)) {
          existing.severity = row.severity;
        }
      }
    }

    // Sort by severity (desc) then count (desc), return top 10
    const sorted = Array.from(typeMap.entries())
      .map(([name, data]) => ({ name, severity: data.severity, count: data.count }))
      .sort((a, b) => {
        const sevDiff = (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0);
        return sevDiff !== 0 ? sevDiff : b.count - a.count;
      })
      .slice(0, 10);

    return { vulnerabilities: sorted };
  }

  // ── Top Coding Vulnerabilities ─────────────────────────────────────────────────

  /**
   * Returns the Top 10 application / code-level vulnerabilities.
   *
   * Classification strategy:
   *   The inverse of getTopPatchingVulnerabilities.
   *   We INCLUDE only records whose `type` field contains one of the well-known
   *   application security keywords (SQL injection, XSS, IDOR, etc.).
   *   This is an OR filter: any match on any keyword qualifies the record.
   *
   * Aggregation strategy:
   *   Identical to patching: single Prisma groupBy on ['type', 'severity'],
   *   entire count runs in PostgreSQL. Small result set merged in Node.js
   *   to resolve highest severity per type, then sorted and sliced.
   */
  async getTopCodingVulnerabilities(
    filter: DashboardFilterDto,
  ): Promise<TopCodingVulnerabilitiesDashboard> {
    const SEV_ORDER: Record<string, number> = {
      CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, INFORMATIONAL: 1,
    };

    // Keywords that identify application / code-level vulnerability types.
    // A vuln is included when its `type` contains ANY of these strings.
    const CODE_LEVEL_KEYWORDS = [
      'injection',
      'xss',
      'cross-site',
      'csrf',
      'xxe',
      'authentication',
      'authoriz',
      'secret',
      'hardcoded',
      'business logic',
      'logic flaw',
      'insecure direct',
      'idor',
      'sast',
      'code review',
      'race condition',
      'deserialization',
      'remote code',
      'rce',
      'path traversal',
      'directory traversal',
      'command injection',
      'open redirect',
      'ssrf',
      'broken access',
      'privilege escalation',
      'session',
      'clickjack',
    ];

    const baseWhere = this.buildVulnWhere(filter);

    // OR filter: include records matching ANY code-level keyword
    const includeFilters: Prisma.VulnerabilityWhereInput[] = CODE_LEVEL_KEYWORDS.map(
      (kw) => ({ type: { contains: kw, mode: 'insensitive' as Prisma.QueryMode } }),
    );

    const where: Prisma.VulnerabilityWhereInput = {
      ...baseWhere,
      OR: includeFilters,
    };

    // Single grouped query — PostgreSQL aggregates count per type + severity
    const groups = await this.prisma.vulnerability.groupBy({
      by: ['type', 'severity'],
      where,
      _count: { _all: true },
    });

    // Merge severity sub-groups for the same type
    const typeMap = new Map<string, { severity: string; count: number }>();
    for (const row of groups) {
      const existing = typeMap.get(row.type);
      if (!existing) {
        typeMap.set(row.type, { severity: row.severity, count: row._count._all });
      } else {
        existing.count += row._count._all;
        if ((SEV_ORDER[row.severity] ?? 0) > (SEV_ORDER[existing.severity] ?? 0)) {
          existing.severity = row.severity;
        }
      }
    }

    const sorted = Array.from(typeMap.entries())
      .map(([name, data]) => ({ name, severity: data.severity, count: data.count }))
      .sort((a, b) => {
        const sevDiff = (SEV_ORDER[b.severity] ?? 0) - (SEV_ORDER[a.severity] ?? 0);
        return sevDiff !== 0 ? sevDiff : b.count - a.count;
      })
      .slice(0, 10);

    return { vulnerabilities: sorted };
  }

  // ── Data Classification Risk ───────────────────────────────────────────────────

  /**
   * Aggregates open vulnerability counts grouped by Application.classification.
   *
   * Aggregation strategy:
   *   1. Fetch distinct non-null Application.classification values (tiny query).
   *   2. Build 2N Prisma count queries (open + critical per classification)
   *      and execute them all in a single $transaction — each count runs as
   *      one SQL statement, pushed entirely to PostgreSQL.
   *   3. Zip results together in Node.js (O(N) on typically 3-5 items).
   *   4. Sort by criticalVulnerabilities desc, then openVulnerabilities desc.
   *
   * N here is the number of distinct classification values — never the number
   * of vulnerabilities — so the transaction size stays constant regardless of
   * data volume.
   */
  async getDataClassificationRisk(
    filter: DashboardFilterDto,
  ): Promise<DataClassificationRiskDashboard> {
    // Step 1: resolve distinct classification labels (typically 3–6 values)
    const appGroups = await this.prisma.application.groupBy({
      by: ['classification'],
      where: { deletedAt: null, classification: { not: null } },
    });

    const classifications = appGroups
      .map((g) => g.classification as string)
      .filter(Boolean);

    if (classifications.length === 0) {
      return { classifications: [] };
    }

    const baseVulnWhere = this.buildVulnWhere(filter);
    const openStatusFilter = { in: ACTIVE_SLA_STATUSES };

    // Step 2: build 2N count queries inside one $transaction
    const openCountQueries = classifications.map((cls) =>
      this.prisma.vulnerability.count({
        where: {
          ...baseVulnWhere,
          status: openStatusFilter,
          request: {
            deletedAt: null,
            targetApp: {
              deletedAt: null,
              classification: cls,
            },
          },
        },
      }),
    );

    const criticalCountQueries = classifications.map((cls) =>
      this.prisma.vulnerability.count({
        where: {
          ...baseVulnWhere,
          status: openStatusFilter,
          severity: Severity.CRITICAL,
          request: {
            deletedAt: null,
            targetApp: {
              deletedAt: null,
              classification: cls,
            },
          },
        },
      }),
    );

    // All 2N queries run as a single database transaction
    const results = await this.prisma.$transaction([
      ...openCountQueries,
      ...criticalCountQueries,
    ]);

    const n = classifications.length;
    const openCounts     = results.slice(0, n);
    const criticalCounts = results.slice(n);

    // Step 3: zip into DTOs
    const rows: DataClassificationRiskDashboard['classifications'] = classifications.map(
      (cls, i) => ({
        classification: cls,
        openVulnerabilities: openCounts[i],
        criticalVulnerabilities: criticalCounts[i],
      }),
    );

    // Step 4: sort by critical desc, then open desc
    rows.sort((a, b) =>
      b.criticalVulnerabilities - a.criticalVulnerabilities ||
      b.openVulnerabilities - a.openVulnerabilities,
    );

    return { classifications: rows };
  }

  // ── BIA Application & Asset Risk ──────────────────────────────────────────────────

  /**
   * Returns Top 10 BIA applications and Top 10 BIA infrastructure assets
   * ranked by vulnerability severity.
   *
   * BIA definition: biaApp = true OR criticality = 'Critical'.
   *
   * Aggregation strategy:
   *   1. Fetch distinct BIA Application IDs + names (small set, rarely >50).
   *   2. Fetch distinct BIA InfrastructureAsset IDs + names.
   *   3. Execute a single $transaction containing 3N queries per entity type:
   *      - open vuln count   (ACTIVE_SLA_STATUSES)
   *      - critical count    (severity = CRITICAL)
   *      - high count        (severity = HIGH)
   *      All counts run as individual SQL COUNT(*) in PostgreSQL.
   *   4. Zip in Node.js (O(N) on a tiny set), sort, slice Top 10.
   *
   *   No raw vulnerability rows are loaded into Node.js at any stage.
   */
  async getBiaApplicationAssetRisk(
    filter: DashboardFilterDto,
  ): Promise<BiaApplicationAssetRiskDashboard> {
    const baseVulnWhere = this.buildVulnWhere(filter);
    const openStatus   = { in: ACTIVE_SLA_STATUSES };

    // ── Step 1: resolve BIA entity IDs ──────────────────────────────────────────────

    const [biaApps, biaInfra] = await this.prisma.$transaction([
      this.prisma.application.findMany({
        where: {
          deletedAt: null,
          OR: [{ biaApp: true }, { criticality: 'Critical' }],
        },
        select: { id: true, name: true },
      }),
      this.prisma.infrastructureAsset.findMany({
        where: {
          deletedAt: null,
          OR: [{ biaApp: true }, { criticality: 'Critical' }],
        },
        select: { id: true, serverName: true },
      }),
    ]);

    if (biaApps.length === 0 && biaInfra.length === 0) {
      return { applications: [], infrastructureAssets: [] };
    }

    // ── Step 2: helper to build 3 count queries per entity ───────────────────────

    const appCountQueries = biaApps.flatMap((app) => [
      // open count
      this.prisma.vulnerability.count({
        where: { ...baseVulnWhere, status: openStatus, request: { deletedAt: null, targetAppId: app.id } },
      }),
      // critical count
      this.prisma.vulnerability.count({
        where: { ...baseVulnWhere, status: openStatus, severity: Severity.CRITICAL, request: { deletedAt: null, targetAppId: app.id } },
      }),
      // high count
      this.prisma.vulnerability.count({
        where: { ...baseVulnWhere, status: openStatus, severity: Severity.HIGH, request: { deletedAt: null, targetAppId: app.id } },
      }),
    ]);

    const infraCountQueries = biaInfra.flatMap((asset) => [
      // open count
      this.prisma.vulnerability.count({
        where: { ...baseVulnWhere, status: openStatus, request: { deletedAt: null, targetInfraId: asset.id } },
      }),
      // critical count
      this.prisma.vulnerability.count({
        where: { ...baseVulnWhere, status: openStatus, severity: Severity.CRITICAL, request: { deletedAt: null, targetInfraId: asset.id } },
      }),
      // high count
      this.prisma.vulnerability.count({
        where: { ...baseVulnWhere, status: openStatus, severity: Severity.HIGH, request: { deletedAt: null, targetInfraId: asset.id } },
      }),
    ]);

    // ── Step 3: single $transaction for all counts ──────────────────────────────

    const results = await this.prisma.$transaction([
      ...appCountQueries,
      ...infraCountQueries,
    ]);

    // ── Step 4: zip and sort ───────────────────────────────────────────────────────

    const sortBia = (items: BiaApplicationAssetRiskDashboard['applications']) =>
      [...items]
        .sort(
          (a, b) =>
            b.criticalVulnerabilities - a.criticalVulnerabilities ||
            b.highVulnerabilities - a.highVulnerabilities ||
            b.openVulnerabilities - a.openVulnerabilities,
        )
        .slice(0, 10);

    // Apps: results[0..3N-1], Infra: results[3N..]
    const na = biaApps.length;
    const applications = sortBia(
      biaApps.map((app, i) => ({
        id: app.id,
        name: app.name,
        openVulnerabilities:     results[i * 3],
        criticalVulnerabilities: results[i * 3 + 1],
        highVulnerabilities:     results[i * 3 + 2],
      })),
    );

    const infraOffset = na * 3;
    const infrastructureAssets = sortBia(
      biaInfra.map((asset, i) => ({
        id: asset.id,
        name: asset.serverName,
        openVulnerabilities:     results[infraOffset + i * 3],
        criticalVulnerabilities: results[infraOffset + i * 3 + 1],
        highVulnerabilities:     results[infraOffset + i * 3 + 2],
      })),
    );

    return { applications, infrastructureAssets };
  }

  // ── New vs Recurring Vulnerabilities ─────────────────────────────────────

  /**
   * Classifies every vulnerability in the filter window as either
   * "new" or "recurring", then buckets both totals into a time-series trend.
   *
   * ── Recurrence Definition ─────────────────────────────────────────────────────────────
   * A vulnerability V is RECURRING when:
   *   - A DIFFERENT, OLDER vulnerability V’ with the same fingerprint exists
   *   - V’ has ever had a VulnerabilityLifecycleLog row with toStatus = CLOSED
   *     or PATCHED (i.e., it was previously remediated).
   *
   * Fingerprint = (requestId, type, source).
   *   • requestId already encodes the target asset (app or infra), the env,
   *     and the security channel — making it a tight discriminator.
   *   • type identifies the vulnerability class ("SQL Injection", "XSS", etc.).
   *   • source distinguishes VAPT findings from Bug Bounty, etc.
   *
   * Long-running OPEN vulnerabilities are never classified as recurring.
   * Only a NEW vuln whose fingerprint matches a previously CLOSED one recurs.
   *
   * ── Aggregation Strategy (no raw rows loaded into Node.js) ────────────────
   * Step 1 — Fetch IDs + fingerprint + createdAt for vulns in the window.
   *           (Only scalar columns, no body text. Typically 100s–low 1000s.)
   * Step 2 — Fetch the set of fingerprints that have a prior CLOSED/PATCHED
   *           lifecycle log entry on an OLDER (different) vulnerability record.
   *           Uses a single queryRawUnsafe joining vulnerabilities on
   *           lifecycle_logs filtered by status.
   * Step 3 — Classify each window vuln in Node.js by set lookup (O(1)).
   * Step 4 — Bucket into trend periods in Node.js from the already-loaded rows.
   *
   * Trend granularity (auto-detected from date range):
   *   • ≤ 14 days  → daily
   *   • ≤ 90 days  → weekly (Mon–Sun buckets)
   *   •  > 90 days → monthly
   */
  async getNewVsRecurringDashboard(
    filter: DashboardFilterDto,
  ): Promise<NewVsRecurringDashboard> {
    const where = this.buildVulnWhere(filter);

    // ── Step 1: Fetch lightweight window rows ──────────────────────────────────
    //
    // Only the columns needed for classification + trend bucketing are selected.
    // No description, poc, remediation, or references text is loaded.

    const windowVulns = await this.prisma.vulnerability.findMany({
      where,
      select: {
        id:        true,
        requestId: true,
        type:      true,
        source:    true,
        createdAt: true,
      },
    });

    if (windowVulns.length === 0) {
      return { newCount: 0, recurringCount: 0, trend: [] };
    }

    // ── Step 2: Detect recurring fingerprints via a single raw SQL query ─────────
    //
    // A fingerprint (requestId, type, source) is “recurring” when there exists
    // an older vulnerability record with the same fingerprint that has at least
    // one lifecycle log row marking it as CLOSED or PATCHED.
    //
    // The query intentionally restricts to vulns created BEFORE each window vuln
    // via v_older.created_at < v_window.created_at to avoid false positives from
    // concurrent OPEN records.
    //
    // Result: one row per unique fingerprint in the window that qualifies as
    // recurring.  Node.js only sees the tiny set of recurring fingerprint tuples.

    const windowIds = windowVulns.map((v) => v.id);

    type RecurringRow = { requestId: string; type: string; source: string };

    // Build a safe parameterised IN list for the window IDs
    // (UUIDs from DB — no user input — but we still use params for correctness)
    const placeholders = windowIds.map((_, i) => `$${i + 1}`).join(', ');

    const recurringRows: RecurringRow[] = await this.prisma.$queryRawUnsafe<RecurringRow[]>(
      `
      SELECT DISTINCT
        v_window."requestId",
        v_window.type,
        v_window.source
      FROM vulnerabilities v_window
      JOIN vulnerabilities v_older
        ON  v_older."requestId" = v_window."requestId"
        AND v_older.type       = v_window.type
        AND v_older.source     = v_window.source
        AND v_older.id        <> v_window.id
        AND v_older."createdAt" < v_window."createdAt"
        AND v_older."deletedAt" IS NULL
      JOIN vulnerability_lifecycle_logs vll
        ON  vll."vulnerabilityId" = v_older.id
        AND vll."toStatus"::text IN ('CLOSED', 'PATCHED')
      WHERE v_window.id IN (${placeholders})
        AND v_window."deletedAt" IS NULL
      `,
      ...windowIds,
    );

    const recurringKeys = new Set<string>(
      recurringRows.map((r) => `${r.requestId}|${r.type}|${r.source}`),
    );

    // ── Step 3 + 4: Classify and bucket in Node.js ─────────────────────────────

    // Determine trend granularity from the selected date range
    const startD = filter.startDate ? new Date(filter.startDate) : null;
    const endD   = filter.endDate   ? new Date(filter.endDate)   : null;

    let granularity: 'daily' | 'weekly' | 'monthly' = 'monthly';
    if (startD && endD) {
      const diffDays = (endD.getTime() - startD.getTime()) / (1000 * 60 * 60 * 24);
      if      (diffDays <= 14) granularity = 'daily';
      else if (diffDays <= 90) granularity = 'weekly';
      else                     granularity = 'monthly';
    } else {
      // No explicit range — derive from the actual data spread
      const dates = windowVulns.map((v) => v.createdAt.getTime());
      const diffDays = (Math.max(...dates) - Math.min(...dates)) / (1000 * 60 * 60 * 24);
      if      (diffDays <= 14) granularity = 'daily';
      else if (diffDays <= 90) granularity = 'weekly';
      else                     granularity = 'monthly';
    }

    /** Derive the period key (ISO date string) for a given timestamp */
    const getPeriodKey = (date: Date): string => {
      if (granularity === 'daily') {
        return date.toISOString().slice(0, 10); // "2026-06-30"
      }
      if (granularity === 'weekly') {
        // Truncate to the nearest Monday
        const d = new Date(date);
        const day = d.getUTCDay(); // 0 = Sun, 1 = Mon …
        const diff = day === 0 ? -6 : 1 - day; // days back to Monday
        d.setUTCDate(d.getUTCDate() + diff);
        return d.toISOString().slice(0, 10);
      }
      // monthly
      return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}-01`;
    };

    // Accumulate totals and per-period buckets in a single pass
    let newCount       = 0;
    let recurringCount = 0;
    const trendMap = new Map<string, { new: number; recurring: number }>();

    for (const v of windowVulns) {
      const key       = `${v.requestId}|${v.type}|${v.source}`;
      const isRecurring = recurringKeys.has(key);
      const period    = getPeriodKey(v.createdAt);

      if (isRecurring) {
        recurringCount++;
      } else {
        newCount++;
      }

      if (!trendMap.has(period)) {
        trendMap.set(period, { new: 0, recurring: 0 });
      }
      const bucket = trendMap.get(period)!;
      if (isRecurring) { bucket.recurring++; } else { bucket.new++; }
    }

    // Sort trend chronologically
    const trend: NewVsRecurringTrendPoint[] = Array.from(trendMap.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([period, counts]) => ({ period, ...counts }));

    return { newCount, recurringCount, trend };
  }

  // ── Repetition Patterns ──────────────────────────────────────────────────

  /**
   * Identifies the Top 10 vulnerability types that appear most repeatedly
   * across assessments within the filter window.
   *
   * ── Repetition Definition ─────────────────────────────────────────────────
   * A vulnerability type is "repeating" when its COUNT(*) across all
   * vulnerability records within the filter window is greater than 1.
   * The panel surfaces systemic patterns (e.g. "SQL Injection appears 42
   * times across 11 applications") rather than individual rediscoveries.
   *
   * ── Aggregation Strategy ─────────────────────────────────────────────────
   * A single raw SQL query performs all work inside PostgreSQL:
   *
   *   SELECT
   *     v.type,
   *     COUNT(*)                                           AS occurrences,
   *     COUNT(DISTINCT sr.target_app_id)                  AS affected_apps,
   *     COUNT(DISTINCT sr.target_infra_id)                AS affected_infra,
   *     MIN(v.created_at)                                 AS first_seen,
   *     MAX(v.created_at)                                 AS last_seen
   *   FROM vulnerabilities v
   *   JOIN security_requests sr ON sr.id = v.request_id
   *   WHERE … filter …
   *   GROUP BY v.type
   *   HAVING COUNT(*) > 1
   *   ORDER BY occurrences DESC,
   *            (COUNT(DISTINCT sr.target_app_id)
   *             + COUNT(DISTINCT sr.target_infra_id)) DESC
   *   LIMIT 10
   *
   * Zero vulnerability rows are transferred to Node.js — only the
   * aggregated summary (at most 10 rows) returns from the database.
   *
   * Parameterisation:
   *   Filter values (environment, startDate, endDate) are passed as
   *   positional parameters ($1…$N) to $queryRawUnsafe to prevent injection.
   */
  async getRepetitionPatternsDashboard(
    filter: DashboardFilterDto,
  ): Promise<RepetitionPatternsDashboard> {
    // ── Build positional WHERE clauses from the filter ────────────────────────
    const params: (string | Date)[] = [];
    const conditions: string[] = [
      'v."deletedAt" IS NULL',
      'sr."deletedAt" IS NULL',
    ];

    if (filter.environment) {
      params.push(filter.environment);
      conditions.push(`v.environment::text = $${params.length}`);
    }
    if (filter.startDate) {
      params.push(new Date(filter.startDate));
      conditions.push(`v."createdAt" >= $${params.length}`);
    }
    if (filter.endDate) {
      params.push(new Date(filter.endDate));
      conditions.push(`v."createdAt" <= $${params.length}`);
    }

    const whereClause = conditions.join(' AND ');

    // ── Single aggregation query ───────────────────────────────────────────
    //
    // target_app_id and target_infra_id are nullable FK columns on
    // security_requests. COUNT(DISTINCT col) ignores NULLs automatically.

    type RawRow = {
      type: string;
      occurrences: bigint;
      affected_apps: bigint;
      affected_infra: bigint;
      first_seen: Date;
      last_seen: Date;
    };

    const rows = await this.prisma.$queryRawUnsafe<RawRow[]>(
      `
      SELECT
        v.type,
        COUNT(*)                             AS occurrences,
        COUNT(DISTINCT sr."targetAppId")     AS affected_apps,
        COUNT(DISTINCT sr."targetInfraId")   AS affected_infra,
        MIN(v."createdAt")                    AS first_seen,
        MAX(v."createdAt")                    AS last_seen
      FROM vulnerabilities v
      JOIN security_requests sr ON sr.id = v."requestId"
      WHERE ${whereClause}
      GROUP BY v.type
      HAVING COUNT(*) > 1
      ORDER BY
        occurrences DESC,
        (COUNT(DISTINCT sr."targetAppId") + COUNT(DISTINCT sr."targetInfraId")) DESC
      LIMIT 10
      `,
      ...params,
    );

    // ── Map raw rows to DTO (only bigint → number coercions needed) ──────────
    const patterns: RepetitionPatternDto[] = rows.map((r) => ({
      type:                        r.type,
      occurrences:                 Number(r.occurrences),
      affectedApplications:        Number(r.affected_apps),
      affectedInfrastructureAssets: Number(r.affected_infra),
      firstSeen:                   r.first_seen,
      lastSeen:                    r.last_seen,
    }));

    return { patterns };
  }

  // ── Security Controls Compliance ────────────────────────────────────────────

  /**
   * GET /dashboard/security-controls-compliance
   *
   * Aggregates vulnerability counts per SecurityControl entirely in PostgreSQL.
   *
   * Algorithm:
   *   1. JOIN vulnerability_control_mappings → vulnerabilities → security_controls
   *   2. COUNT(*) = total findings per control
   *   3. COUNT WHERE status = 'CLOSED' = closed findings
   *   4. total - closed = open findings
   *   5. compliance% = closed / (closed + open) × 100
   *
   * Applies environment + date filters on vulnerabilities.created_at.
   * Controls with 0 findings are excluded (no evidence).
   * Sorted: lowest compliance first, then highest total findings.
   */
  async getSecurityControlsComplianceDashboard(
    filter: DashboardFilterDto,
  ): Promise<SecurityControlsComplianceDashboard> {
    const conditions: string[] = [
      `v."deletedAt" IS NULL`,
      `sc."isActive" = true`,
    ];
    const params: (string | Date)[] = [];
    let idx = 1;

    if (filter.environment) {
      conditions.push(`v.environment::text = $${idx++}`);
      params.push(filter.environment);
    }
    if (filter.startDate) {
      conditions.push(`v."createdAt" >= $${idx++}`);
      params.push(new Date(filter.startDate));
    }
    if (filter.endDate) {
      conditions.push(`v."createdAt" <= $${idx++}`);
      params.push(new Date(filter.endDate));
    }

    const whereClause = conditions.join(' AND ');

    type RawRow = {
      control_id:    string;
      control_key:   string;
      control_name:  string;
      category:      string;
      total_findings: bigint;
      open_findings:  bigint;
      closed_findings: bigint;
    };

    // Open = any non-CLOSED, non-deleted status
    // Closed = status = 'CLOSED'
    const rows = await this.prisma.$queryRawUnsafe<RawRow[]>(
      `
      SELECT
        sc.id                                                 AS control_id,
        sc."controlKey"                                       AS control_key,
        sc.name                                               AS control_name,
        sc.category                                           AS category,
        COUNT(*)                                              AS total_findings,
        COUNT(*) FILTER (WHERE v.status::text != 'CLOSED')    AS open_findings,
        COUNT(*) FILTER (WHERE v.status::text = 'CLOSED')     AS closed_findings
      FROM vulnerability_control_mappings vcm
      JOIN vulnerabilities    v  ON v.id  = vcm."vulnerabilityId"
      JOIN security_controls  sc ON sc.id = vcm."controlId"
      WHERE ${whereClause}
      GROUP BY sc.id, sc."controlKey", sc.name, sc.category
      HAVING COUNT(*) > 0
      ORDER BY
        (COUNT(*) FILTER (WHERE v.status::text = 'CLOSED'))::float
          / NULLIF(COUNT(*), 0) ASC,
        COUNT(*) DESC
      `,
      ...params,
    );

    const controls: SecurityControlComplianceDto[] = rows.map((r) => {
      const total  = Number(r.total_findings);
      const closed = Number(r.closed_findings);
      const open   = Number(r.open_findings);
      const pct    = total > 0 ? Math.round((closed / total) * 1000) / 10 : 0;
      return {
        controlId:            r.control_id,
        controlKey:           r.control_key,
        controlName:          r.control_name,
        category:             r.category,
        totalFindings:        total,
        openFindings:         open,
        closedFindings:       closed,
        compliancePercentage: pct,
      };
    });

    // Overall weighted compliance
    const sumClosed = controls.reduce((s, c) => s + c.closedFindings, 0);
    const sumTotal  = controls.reduce((s, c) => s + c.totalFindings,  0);
    const overall   = sumTotal > 0
      ? Math.round((sumClosed / sumTotal) * 1000) / 10
      : 0;

    return {
      controls,
      overallCompliancePercentage: overall,
      totalControls:       controls.length,
      compliantControls:   controls.filter((c) => c.compliancePercentage >= 90).length,
      atRiskControls:      controls.filter((c) => c.compliancePercentage >= 70 && c.compliancePercentage < 90).length,
      nonCompliantControls: controls.filter((c) => c.compliancePercentage < 70).length,
    };
  }
}
