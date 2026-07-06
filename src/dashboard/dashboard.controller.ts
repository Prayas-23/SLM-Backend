import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { DashboardService } from './dashboard.service';
import { DashboardFilterDto } from './dashboard.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

/**
 * All roles that are permitted to view dashboard data.
 * SECURITY_LEAD, SECURITY_ANALYST, APPLICATION_OWNER,
 * INFRASTRUCTURE_OWNER, and READ_ONLY can all access dashboards.
 */
const DASHBOARD_ROLES = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
  UserRole.APPLICATION_OWNER,
  UserRole.INFRASTRUCTURE_OWNER,
  UserRole.READ_ONLY,
];

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  /**
   * GET /dashboard/overview
   *
   * High-level KPIs:
   *   totalApplications, totalInfrastructureAssets, totalCloudResources,
   *   totalSecurityRequests, totalVulnerabilities, openVulnerabilities,
   *   closedVulnerabilities, slaCompliancePercentage
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('overview')
  @Roles(...DASHBOARD_ROLES)
  getOverview(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getOverview(filter);
  }

  /**
   * GET /dashboard/vulnerabilities
   *
   * Breakdown by:
   *   - Severity  (CRITICAL / HIGH / MEDIUM / LOW / INFORMATIONAL)
   *   - Status    (OPEN / ASSIGNED / IN_PROGRESS / PATCHED / PENDING_REVALIDATION / CLOSED)
   *   - Source    (VAPT / BUG_BOUNTY / RED_TEAM / CLOUDSEK)
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('vulnerabilities')
  @Roles(...DASHBOARD_ROLES)
  getVulnerabilities(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getVulnerabilityDashboard(filter);
  }

  /**
   * GET /dashboard/security-requests
   *
   * Breakdown by source and status, plus open/closed counts.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('security-requests')
  @Roles(...DASHBOARD_ROLES)
  getSecurityRequests(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getSecurityRequestDashboard(filter);
  }

  /**
   * GET /dashboard/sla
   *
   * Reuses Phase 2F SlaMetricsService.
   * Returns: total, withinSla, breached, critBreached, highBreached,
   *          compliancePct, complianceBySeverity[], complianceByEnvironment[]
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('sla')
  @Roles(...DASHBOARD_ROLES)
  getSla(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getSlaDashboard(filter);
  }

  /**
   * GET /dashboard/applications
   *
   * Returns:
   *   - topVulnerableApplications (top 10)
   *   - applicationVulnerabilityCounts (all apps)
   *   - applicationSlaCompliance (SLA status per app)
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('applications')
  @Roles(...DASHBOARD_ROLES)
  getApplications(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getApplicationDashboard(filter);
  }

  /**
   * GET /dashboard/infrastructure
   *
   * Returns:
   *   - topVulnerableAssets (top 10)
   *   - infrastructureVulnerabilityCounts (all assets)
   *   - infrastructureSlaCompliance (SLA status per asset)
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('infrastructure')
  @Roles(...DASHBOARD_ROLES)
  getInfrastructure(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getInfrastructureDashboard(filter);
  }

  /**
   * GET /dashboard/cloud
   *
   * Returns:
   *   - cloudResourcesByProvider (AWS / Azure / GCP)
   *   - cloudResourcesByType (Compute / Database / Container / Storage / Network / Security / Other)
   *
   * Query params: environment?
   */
  @Get('cloud')
  @Roles(...DASHBOARD_ROLES)
  getCloud(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getCloudDashboard(filter);
  }

  @Get('common-vulnerabilities')
  @Roles(...DASHBOARD_ROLES)
  getCommonVulnerabilities(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getCommonVulnerabilitiesDashboard(filter);
  }

  @Get('health-scorecards')
  @Roles(...DASHBOARD_ROLES)
  getHealthScorecards(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getHealthScorecardsDashboard(filter);
  }

  @Get('owner-performance')
  @Roles(...DASHBOARD_ROLES)
  getOwnerPerformance(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getOwnerPerformanceDashboard(filter);
  }

  @Get('vapt-schedule')
  @Roles(...DASHBOARD_ROLES)
  getVaptSchedule() {
    return this.dashboardService.getVaptScheduleDashboard();
  }

  /**
   * GET /dashboard/bia-risk-metrics
   *
   * Returns three Business Impact Analysis KPI counts:
   *   biaAppsCritical   — BIA applications with ≥1 open CRITICAL/HIGH vulnerability
   *   biaInfraCritical  — BIA infrastructure assets with ≥1 open CRITICAL/HIGH vulnerability
   *   biaAssetsBreached — BIA apps + infra with ≥1 active SLA breach
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('bia-risk-metrics')
  @Roles(...DASHBOARD_ROLES)
  getBiaRiskMetrics(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getBiaRiskMetrics(filter);
  }

  /**
   * GET /dashboard/top-patching-vulnerabilities
   *
   * Returns up to 10 infrastructure/OS/middleware patching vulnerability types.
   * Excludes code-level vulnerability classes (XSS, injection, auth, etc.).
   * Sorted by highest severity, then by occurrence count.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('top-patching-vulnerabilities')
  @Roles(...DASHBOARD_ROLES)
  getTopPatchingVulnerabilities(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getTopPatchingVulnerabilities(filter);
  }

  /**
   * GET /dashboard/top-coding-vulnerabilities
   *
   * Returns up to 10 application/code-level vulnerability types.
   * Includes only code-security classes (XSS, injection, IDOR, auth, etc.).
   * Excludes OS/middleware patching issues.
   * Sorted by highest severity, then by occurrence count.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('top-coding-vulnerabilities')
  @Roles(...DASHBOARD_ROLES)
  getTopCodingVulnerabilities(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getTopCodingVulnerabilities(filter);
  }

  /**
   * GET /dashboard/data-classification-risk
   *
   * Returns open and critical vulnerability counts grouped by
   * Application.classification (e.g. Internal, Restricted, Internet Facing).
   * Sorted by critical desc, then total open desc.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('data-classification-risk')
  @Roles(...DASHBOARD_ROLES)
  getDataClassificationRisk(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getDataClassificationRisk(filter);
  }

  /**
   * GET /dashboard/bia-application-asset-risk
   *
   * Returns Top 10 BIA applications and Top 10 BIA infrastructure assets
   * ranked by critical → high → total open vulnerability count.
   * BIA = biaApp:true OR criticality:'Critical'.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('bia-application-asset-risk')
  @Roles(...DASHBOARD_ROLES)
  getBiaApplicationAssetRisk(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getBiaApplicationAssetRisk(filter);
  }

  /**
   * GET /dashboard/new-vs-recurring-vulnerabilities
   *
   * Classifies all vulnerabilities in the filter window as new or recurring,
   * and returns both totals plus a time-series trend bucketed by period
   * (daily / weekly / monthly, auto-selected based on the date range).
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('new-vs-recurring-vulnerabilities')
  @Roles(...DASHBOARD_ROLES)
  getNewVsRecurring(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getNewVsRecurringDashboard(filter);
  }

  /**
   * GET /dashboard/repetition-patterns
   *
   * Returns the Top 10 vulnerability types that appear most frequently
   * across assessments in the filter window, with per-type counts of
   * distinct affected applications and infrastructure assets.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('repetition-patterns')
  @Roles(...DASHBOARD_ROLES)
  getRepetitionPatterns(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getRepetitionPatternsDashboard(filter);
  }

  /**
   * GET /dashboard/security-controls-compliance
   *
   * Returns per-control compliance percentages derived from
   * VulnerabilityControlMapping + Vulnerability tables.
   * Controls with no mapped vulnerabilities are excluded.
   *
   * Query params: environment?, startDate?, endDate?
   */
  @Get('security-controls-compliance')
  @Roles(...DASHBOARD_ROLES)
  getSecurityControlsCompliance(@Query() filter: DashboardFilterDto) {
    return this.dashboardService.getSecurityControlsComplianceDashboard(filter);
  }
}
