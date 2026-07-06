import {
  IsOptional,
  IsEnum,
  IsDateString,
} from 'class-validator';
import {
  Environment,
  Severity,
  VulnerabilityStatus,
  CloudProvider,
  CloudResourceType,
} from '@prisma/client';

// ── Request Filter ─────────────────────────────────────────────────────────────

export class DashboardFilterDto {
  /**
   * Optional environment scope.
   * Omit (or pass nothing) to query ALL environments.
   */
  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  /**
   * ISO 8601 start date for the reporting window.
   * Filters vulnerability.createdAt / securityRequest.createdAt >= startDate
   */
  @IsOptional()
  @IsDateString()
  startDate?: string;

  /**
   * ISO 8601 end date for the reporting window.
   * Filters vulnerability.createdAt / securityRequest.createdAt <= endDate
   */
  @IsOptional()
  @IsDateString()
  endDate?: string;
}

// ── Overview Response ──────────────────────────────────────────────────────────

export interface OverviewMetrics {
  totalApplications: number;
  totalInfrastructureAssets: number;
  totalCloudResources: number;
  totalSecurityRequests: number;
  totalVulnerabilities: number;
  openVulnerabilities: number;
  closedVulnerabilities: number;
  /** Percentage of active vulnerabilities within their SLA due-date (0–100) */
  slaCompliancePercentage: number;
  openCvsFindings: number;
}

// ── Vulnerability Dashboard Response ──────────────────────────────────────────

export interface SeverityCount {
  severity: Severity;
  count: number;
}

export interface StatusCount {
  status: VulnerabilityStatus;
  count: number;
}

export interface SourceVulnCount {
  source: string;
  count: number;
}

export interface VulnerabilityDashboard {
  severityBreakdown: SeverityCount[];
  statusBreakdown: StatusCount[];
  sourceBreakdown: SourceVulnCount[];
}

// ── Security Request Dashboard Response ───────────────────────────────────────

export interface RequestSourceCount {
  source: string;
  count: number;
}

export interface RequestStatusCount {
  status: string;
  count: number;
}

export interface SecurityRequestDashboard {
  requestCountBySource: RequestSourceCount[];
  requestCountByStatus: RequestStatusCount[];
  openRequests: number;
  closedRequests: number;
}

// ── SLA Dashboard Response ────────────────────────────────────────────────────

export interface SlaSeverityCompliance {
  severity: Severity;
  total: number;
  compliant: number;
  breached: number;
  compliancePct: number;
}

export interface SlaEnvironmentCompliance {
  environment: Environment;
  total: number;
  compliant: number;
  breached: number;
  compliancePct: number;
}

export interface SlaDashboard {
  total: number;
  withinSla: number;
  breached: number;
  critBreached: number;
  highBreached: number;
  compliancePct: number;
  complianceBySeverity: SlaSeverityCompliance[];
  complianceByEnvironment: SlaEnvironmentCompliance[];
}

// ── Application Dashboard Response ────────────────────────────────────────────

export interface AppVulnCount {
  applicationId: string;
  applicationName: string;
  vulnerabilityCount: number;
}

export interface AppSlaCompliance {
  applicationId: string;
  applicationName: string;
  total: number;
  compliant: number;
  breached: number;
  compliancePct: number;
}

export interface ApplicationDashboard {
  /** Top 10 applications ranked by vulnerability count (descending) */
  topVulnerableApplications: AppVulnCount[];
  /** Full list of application → vulnerability count */
  applicationVulnerabilityCounts: AppVulnCount[];
  /** SLA compliance per application */
  applicationSlaCompliance: AppSlaCompliance[];
}

// ── Infrastructure Dashboard Response ─────────────────────────────────────────

export interface InfraVulnCount {
  assetId: string;
  assetName: string;
  vulnerabilityCount: number;
}

export interface InfraSlaCompliance {
  assetId: string;
  assetName: string;
  total: number;
  compliant: number;
  breached: number;
  compliancePct: number;
}

export interface InfrastructureDashboard {
  /** Top 10 infrastructure assets ranked by vulnerability count (descending) */
  topVulnerableAssets: InfraVulnCount[];
  infrastructureVulnerabilityCounts: InfraVulnCount[];
  infrastructureSlaCompliance: InfraSlaCompliance[];
}

// ── Cloud Dashboard Response ───────────────────────────────────────────────────

export interface CloudProviderCount {
  provider: CloudProvider;
  count: number;
}

export interface CloudTypeCount {
  type: CloudResourceType;
  count: number;
}

export interface CloudDashboard {
  cloudResourcesByProvider: CloudProviderCount[];
  cloudResourcesByType: CloudTypeCount[];
}

// ── Common Vulnerabilities Response ──────────────────────────────────────────

export interface CommonVulnCount {
  type: string;
  severity: Severity;
  source: string;
  count: number;
}

export interface CommonVulnerabilitiesDashboard {
  commonVulnerabilities: CommonVulnCount[];
}

// ── Health Scorecards Response ───────────────────────────────────────────────

export interface ApplicationHealthScorecard {
  applicationId: string;
  applicationName: string;
  ownerName: string | null;
  score: number;
  slaCompliancePct: number;
  patchCompliancePct: number;
  lastVaptDate: Date | null;
  nextVaptDate: Date | null;
  healthStatus: 'Healthy' | 'At Risk' | 'Critical';
}

export interface HealthScorecardsDashboard {
  scorecards: ApplicationHealthScorecard[];
}

// ── Owner Performance Response ───────────────────────────────────────────────

export interface OwnerPerformance {
  ownerId: string;
  ownerName: string;
  role: string;
  assignedFindings: number;
  patchedOnTime: number;
  closedFindings: number;
  slaBreaches: number;
  closurePercentage: number;
  breachRate: number;
  grade: 'A' | 'B' | 'C' | 'D';
}

export interface OwnerPerformanceDashboard {
  ownerPerformances: OwnerPerformance[];
}

// ── VAPT Schedule Response ───────────────────────────────────────────────────

export interface VaptScheduleItem {
  assetId: string;
  assetName: string;
  assetType: 'Application' | 'Infra';
  vaptStatus: string;
  dueDate: Date | null;
  overdueDays: number | null;
  ownerInitials: string;
}

export interface VaptScheduleDashboard {
  schedule: VaptScheduleItem[];
}

// ── BIA Risk Metrics Response ─────────────────────────────────────────────────

/**
 * Business Impact Analysis (BIA) risk KPIs.
 *
 * "BIA" assets = Applications / Infrastructure Assets where criticality = 'Critical'.
 *
 * biaAppsCritical   — BIA applications with ≥1 open CRITICAL or HIGH vulnerability.
 * biaInfraCritical  — BIA infrastructure assets with ≥1 open CRITICAL or HIGH vulnerability.
 * biaAssetsBreached — BIA assets (apps + infra) with ≥1 active SLA breach.
 */
export interface BiaRiskMetrics {
  biaAppsCritical: number;
  biaInfraCritical: number;
  biaAssetsBreached: number;
}

// ── Top Patching Vulnerabilities Response ─────────────────────────────────────

/**
 * A single entry in the Top Patching Vulnerabilities list.
 *
 * name     — The vulnerability `type` field (OS / middleware / package class).
 * severity — The highest severity found across all matching records.
 * count    — Total number of occurrences of this vulnerability type.
 */
export interface TopPatchingVulnerabilityDto {
  name: string;
  severity: string;
  count: number;
}

export interface TopPatchingVulnerabilitiesDashboard {
  vulnerabilities: TopPatchingVulnerabilityDto[];
}

// ── Top Coding Vulnerabilities Response ───────────────────────────────────────

/**
 * A single entry in the Top Coding Vulnerabilities list.
 *
 * name     — The vulnerability `type` field (e.g. SQL Injection, XSS, IDOR).
 * severity — The highest severity found across all matching records.
 * count    — Total number of occurrences of this vulnerability type.
 */
export interface TopCodingVulnerabilityDto {
  name: string;
  severity: string;
  count: number;
}

export interface TopCodingVulnerabilitiesDashboard {
  vulnerabilities: TopCodingVulnerabilityDto[];
}

// ── Data Classification Risk Response ─────────────────────────────────────────

/**
 * Vulnerability risk aggregated by the Application.classification field.
 *
 * classification         — The free-text classification label (e.g. "Internal",
 *                          "Restricted", "Internet Facing").
 * openVulnerabilities    — Total active (non-closed) vulnerabilities linked to
 *                          applications with this classification.
 * criticalVulnerabilities — Subset of openVulnerabilities where severity = CRITICAL.
 */
export interface DataClassificationRiskDto {
  classification: string;
  openVulnerabilities: number;
  criticalVulnerabilities: number;
}

export interface DataClassificationRiskDashboard {
  classifications: DataClassificationRiskDto[];
}

// ── BIA Application & Asset Risk Response ──────────────────────────────────────────────

/**
 * A single BIA application or infrastructure asset with its
 * vulnerability risk breakdown.
 */
export interface BiaAssetRiskItem {
  id: string;
  name: string;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  openVulnerabilities: number;
}

export interface BiaApplicationAssetRiskDashboard {
  applications: BiaAssetRiskItem[];
  infrastructureAssets: BiaAssetRiskItem[];
}

// ── New vs Recurring Vulnerabilities Response ──────────────────────────────────

/**
 * A single period bucket in the New vs Recurring trend chart.
 *
 * period — ISO date string representing the start of the bucket:
 *          daily   → "2026-06-30"
 *          weekly  → "2026-06-30" (Monday of the week)
 *          monthly → "2026-06-01" (first of the month)
 */
export interface NewVsRecurringTrendPoint {
  period: string;
  new: number;
  recurring: number;
}

export interface NewVsRecurringDashboard {
  /** Total new vulnerabilities within the filter window */
  newCount: number;
  /** Total recurring vulnerabilities within the filter window */
  recurringCount: number;
  /** Time-series trend bucketed by period */
  trend: NewVsRecurringTrendPoint[];
}

// ── Repetition Patterns Response ───────────────────────────────────────────

/**
 * A single vulnerability type that repeatedly appears across assessments.
 *
 * type                        — The normalized vulnerability class (e.g. "SQL Injection").
 * occurrences                 — Total number of vulnerability records of this type.
 * affectedApplications        — Distinct applications that have at least one occurrence.
 * affectedInfrastructureAssets — Distinct infrastructure assets with at least one occurrence.
 * firstSeen                   — Earliest createdAt across all occurrences.
 * lastSeen                    — Most recent createdAt across all occurrences.
 */
export interface RepetitionPatternDto {
  type: string;
  occurrences: number;
  affectedApplications: number;
  affectedInfrastructureAssets: number;
  firstSeen: Date;
  lastSeen: Date;
}

export interface RepetitionPatternsDashboard {
  patterns: RepetitionPatternDto[];
}

// ── Security Controls Compliance Response ────────────────────────────────────

/**
 * Compliance posture for one SecurityControl.
 *
 * Calculated entirely from VulnerabilityControlMapping + Vulnerability tables.
 * Controls with zero findings are excluded (no evidence = excluded).
 *
 * compliancePercentage = closedFindings / (closedFindings + openFindings) × 100
 * Rounds to 1 decimal place.
 */
export interface SecurityControlComplianceDto {
  controlId: string;
  controlKey: string;
  controlName: string;
  category: string;
  totalFindings: number;
  openFindings: number;
  closedFindings: number;
  compliancePercentage: number;
}

export interface SecurityControlsComplianceDashboard {
  controls: SecurityControlComplianceDto[];
  /** Weighted overall compliance: sum(closed) / sum(closed+open) × 100 */
  overallCompliancePercentage: number;
  totalControls: number;
  compliantControls: number;   // ≥ 90%
  atRiskControls: number;      // 70–89%
  nonCompliantControls: number; // < 70%
}
