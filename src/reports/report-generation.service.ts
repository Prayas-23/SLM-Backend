import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ReportType, ReportFormat } from './dto/report.dto';
import { Environment, Severity, VulnerabilityStatus, AuditAction, AuditEntityType, CvsAssignmentMethod } from '@prisma/client';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { CsvBuilder } from './csv-builder';

// ── ExcelJS (optional dep — install: npm install exceljs) ─────────────────────
// eslint-disable-next-line @typescript-eslint/no-var-requires
let ExcelJS: typeof import('exceljs') | null = null;
try {
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  ExcelJS = require('exceljs');
} catch {
  // exceljs not installed — XLSX generation will throw a descriptive error
}

// ── Constants ─────────────────────────────────────────────────────────────────
export const REPORTS_DIR = path.join(process.cwd(), 'uploads', 'reports');
const REPORT_EXPIRY_HOURS = 72;

export interface GenerationContext {
  reportId: string;
  type: ReportType;
  format: ReportFormat;
  environment?: Environment;
  startDate?: string;
  endDate?: string;
  severity?: Severity;
  status?: string;
  source?: string;
  assignmentMethod?: CvsAssignmentMethod;
  owner?: string;
  asset?: string;
  application?: string;
  myPending?: string;
  actorId?: string;
  extraFilters?: Record<string, any>;
}

@Injectable()
export class ReportGenerationService {
  private readonly logger = new Logger(ReportGenerationService.name);

  constructor(private readonly prisma: PrismaService) {}

  // ── Entry point ─────────────────────────────────────────────────────────────

  async generate(ctx: GenerationContext): Promise<{ storageKey: string; url: string }> {
    this.logger.log(`Generating report [${ctx.type}] in [${ctx.format}] — id: ${ctx.reportId}`);

    const rows = await this.fetchData(ctx);
    const { storageKey, url } = await this.writeFile(ctx, rows);
    // Log audit entry for report generation
    await this.prisma.auditLog.create({
      data: {
        entityType: AuditEntityType.REPORT,
        entityId: storageKey,
        action: AuditAction.CREATED,
        metadata: {
          reportId: ctx.reportId,
          type: ctx.type,
          format: ctx.format,
          filters: ctx,
        } as never,
      },
    });
    return { storageKey, url };
  }

  // ── Data fetcher router ─────────────────────────────────────────────────────

  private async fetchData(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    switch (ctx.type) {
      case ReportType.VULNERABILITIES:
        return this.fetchVulnerabilities(ctx);
      case ReportType.SECURITY_REQUESTS:
        return this.fetchSecurityRequests(ctx);
      case ReportType.SLA:
        return this.fetchSla(ctx);
      case ReportType.APPLICATIONS:
        return this.fetchApplications(ctx);
      case ReportType.INFRASTRUCTURE_ASSETS:
        return this.fetchInfrastructureAssets(ctx);
      case ReportType.CLOUD_RESOURCES:
        return this.fetchCloudResources(ctx);
      case ReportType.EXECUTIVE_DASHBOARD:
        return this.fetchExecutiveDashboard(ctx);
      case ReportType.CONTINUOUS_SCAN_FINDINGS:
        return this.fetchContinuousScanFindings(ctx);
      default:
        throw new Error(`Unknown report type: ${ctx.type as string}`);
    }
  }

  // ── Data Fetchers ───────────────────────────────────────────────────────────

  private buildDateFilter(ctx: GenerationContext, field = 'createdAt') {
    if (!ctx.startDate && !ctx.endDate) return {};
    return {
      [field]: {
        ...(ctx.startDate && { gte: new Date(ctx.startDate) }),
        ...(ctx.endDate && { lte: new Date(ctx.endDate) }),
      },
    };
  }

  private async fetchVulnerabilities(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const where: any = {
      deletedAt: null,
      ...(ctx.environment && { environment: ctx.environment }),
      ...this.buildDateFilter(ctx, 'createdAt'),
    };
    if (ctx.source) where.source = ctx.source;
    if (ctx.severity) where.severity = ctx.severity;
    if (ctx.status) where.status = ctx.status;

    const extra = ctx.extraFilters || {};
    if (extra.search) {
      where.OR = [
        ...(where.OR || []),
        { vulnId: { contains: extra.search, mode: 'insensitive' } },
        { shortDesc: { contains: extra.search, mode: 'insensitive' } },
        { type: { contains: extra.search, mode: 'insensitive' } },
        { cve: { contains: extra.search, mode: 'insensitive' } },
        { assignedTo: { name: { contains: extra.search, mode: 'insensitive' } } },
      ];
    }

    const rows = await this.prisma.vulnerability.findMany({
      where,
      select: {
        vulnId: true, source: true, environment: true, type: true,
        shortDesc: true, severity: true, status: true, cvss: true, cve: true,
        affectedComponent: true, reportedBy: true, reportedOn: true,
        slaDueDate: true, closedAt: true, createdAt: true,
        assignedTo: { select: { name: true, email: true } },
        request: { select: { reqId: true } },
        slaTracking: { select: { isBreached: true, daysRemaining: true } },
      },
      orderBy: [{ severity: 'asc' }, { createdAt: 'desc' }],
    });

    return rows.map((v) => ({
      'Vuln ID': v.vulnId,
      'Request ID': v.request?.reqId ?? '',
      Source: v.source,
      Environment: v.environment,
      Type: v.type,
      'Short Description': v.shortDesc,
      Severity: v.severity,
      Status: v.status,
      CVSS: v.cvss ?? '',
      CVE: v.cve ?? '',
      'Affected Component': v.affectedComponent ?? '',
      'Reported By': v.reportedBy ?? '',
      'Reported On': v.reportedOn?.toISOString().split('T')[0] ?? '',
      'SLA Due Date': v.slaDueDate?.toISOString().split('T')[0] ?? '',
      'SLA Breached': v.slaTracking?.isBreached ? 'Yes' : 'No',
      'Days Remaining': v.slaTracking?.daysRemaining ?? '',
      'Assigned To': v.assignedTo?.name ?? '',
      'Assignee Email': v.assignedTo?.email ?? '',
      'Closed At': v.closedAt?.toISOString().split('T')[0] ?? '',
      'Created At': v.createdAt.toISOString().split('T')[0],
    }));
  }

  private async fetchSecurityRequests(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const where: any = {
      deletedAt: null,
      ...(ctx.environment && { environment: ctx.environment }),
      ...(ctx.myPending === 'true' && ctx.actorId && { assignedToId: ctx.actorId }),
      ...(ctx.myPending === 'true' && !ctx.status && { status: { not: 'CLOSED' } }),
      ...this.buildDateFilter(ctx, 'createdAt'),
    };
    if (ctx.source) where.source = ctx.source;
    if (ctx.status) where.status = ctx.status;

    const extra = ctx.extraFilters || {};
    if (extra.reqId) where.reqId = { contains: extra.reqId, mode: 'insensitive' };
    if (extra.appName) {
      where.targetApp = { name: { contains: extra.appName, mode: 'insensitive' } };
    }
    if (extra.initiatedBy) {
      where.initiatedBy = { name: { contains: extra.initiatedBy, mode: 'insensitive' } };
    }
    if (extra.assignedTo) {
      where.assignedTo = { name: { contains: extra.assignedTo, mode: 'insensitive' } };
    }
    if (extra.search) {
      where.OR = [
        ...(where.OR || []),
        { reqId: { contains: extra.search, mode: 'insensitive' } },
        { targetApp: { name: { contains: extra.search, mode: 'insensitive' } } },
        { targetInfra: { serverName: { contains: extra.search, mode: 'insensitive' } } },
        { initiatedBy: { name: { contains: extra.search, mode: 'insensitive' } } },
        { assignedTo: { name: { contains: extra.search, mode: 'insensitive' } } },
      ];
    }

    const rows = await this.prisma.securityRequest.findMany({
      where,
      select: {
        reqId: true, source: true, environment: true, status: true,
        partner: true, initiatedOn: true, submittedAt: true,
        startedAt: true, findingsSharedAt: true, closedAt: true,
        targetApp: { select: { name: true } },
        targetInfra: { select: { serverName: true } },
        initiatedBy: { select: { name: true, email: true } },
        assignedTo: { select: { name: true, email: true } },
        // ── Canonical source: Vulnerability records ──────────────────
        vulnerabilities: {
          where: { deletedAt: null },
          select: { severity: true, status: true, slaDueDate: true },
        },
      },
      orderBy: { initiatedOn: 'desc' },
    });

    const now = new Date();

    return rows.map((r) => {
      const vulns = r.vulnerabilities ?? [];
      const totalVulns   = vulns.length;
      const openVulns    = vulns.filter((v) => v.status !== 'CLOSED').length;
      const critVulns    = vulns.filter((v) => v.status !== 'CLOSED' && v.severity === 'CRITICAL').length;
      const highVulns    = vulns.filter((v) => v.status !== 'CLOSED' && v.severity === 'HIGH').length;
      const withSla      = vulns.filter((v) => v.status !== 'CLOSED' && v.slaDueDate);
      const compliantSla = withSla.filter((v) => new Date(v.slaDueDate!) >= now).length;
      const slaCompliancePct = withSla.length > 0
        ? Math.round((compliantSla / withSla.length) * 100)
        : 100;

      return {
        'Request ID': r.reqId,
        Source: r.source,
        Environment: r.environment,
        Status: r.status,
        Partner: r.partner ?? '',
        'Target Application': r.targetApp?.name ?? '',
        'Target Infrastructure': r.targetInfra?.serverName ?? '',
        'Initiated By': r.initiatedBy?.name ?? '',
        'Initiated On': r.initiatedOn.toISOString().split('T')[0],
        'Submitted At': r.submittedAt?.toISOString().split('T')[0] ?? '',
        'Started At': r.startedAt?.toISOString().split('T')[0] ?? '',
        'Findings Shared At': r.findingsSharedAt?.toISOString().split('T')[0] ?? '',
        'Closed At': r.closedAt?.toISOString().split('T')[0] ?? '',
        // ── Canonical counters derived from Vulnerability records ──────
        'Total Vulnerabilities': totalVulns,
        'Open Vulnerabilities': openVulns,
        'Critical Vulnerabilities': critVulns,
        'High Vulnerabilities': highVulns,
        'SLA Compliance %': slaCompliancePct,
        'Assigned To': r.assignedTo?.name ?? '',
      };
    });
  }


  private async fetchSla(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const now = new Date();
    const vulnWhere: Record<string, unknown> = {
      deletedAt: null,
      status: {
        in: [
          VulnerabilityStatus.OPEN,
          VulnerabilityStatus.ASSIGNED,
          VulnerabilityStatus.IN_PROGRESS,
          VulnerabilityStatus.PATCHED,
          VulnerabilityStatus.PENDING_REVALIDATION,
        ],
      },
      ...(ctx.environment && { environment: ctx.environment }),
      ...this.buildDateFilter(ctx, 'createdAt'),
    };

    const rows = await this.prisma.vulnerability.findMany({
      where: vulnWhere,
      select: {
        vulnId: true, severity: true, status: true, environment: true,
        slaDueDate: true,
        slaTracking: { select: { isBreached: true, daysRemaining: true, breachedAt: true } },
        request: { select: { reqId: true } },
        assignedTo: { select: { name: true, email: true } },
      },
      orderBy: { slaDueDate: 'asc' },
    });

    return rows.map((v) => {
      const due = v.slaDueDate ? new Date(v.slaDueDate) : null;
      const daysLeft = due ? Math.ceil((due.getTime() - now.getTime()) / 86400000) : null;
      return {
        'Vuln ID': v.vulnId,
        'Request ID': v.request?.reqId ?? '',
        Severity: v.severity,
        Status: v.status,
        Environment: v.environment,
        'SLA Due Date': v.slaDueDate?.toISOString().split('T')[0] ?? '',
        'Days Remaining': daysLeft ?? '',
        'Is Breached': v.slaTracking?.isBreached ? 'Yes' : 'No',
        'Breached At': v.slaTracking?.breachedAt?.toISOString().split('T')[0] ?? '',
        'Assigned To': v.assignedTo?.name ?? '',
        'Assignee Email': v.assignedTo?.email ?? '',
      };
    });
  }

  private async fetchApplications(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const where: any = {
      deletedAt: null,
      ...(ctx.environment && { environment: ctx.environment }),
    };

    const extra = ctx.extraFilters || {};
    if (extra.appId) where.appId = { contains: extra.appId, mode: 'insensitive' };
    if (extra.name) where.name = { contains: extra.name, mode: 'insensitive' };
    if (extra.type) where.type = extra.type;
    if (extra.department) where.department = { contains: extra.department, mode: 'insensitive' };
    if (extra.vaptStatus) where.vaptStatus = extra.vaptStatus;
    if (extra.criticality) where.criticality = extra.criticality;
    if (extra.ownerName) {
      where.OR = [
        ...(where.OR || []),
        { owner: { name: { contains: extra.ownerName, mode: 'insensitive' } } },
        { ownerEmail: { contains: extra.ownerName, mode: 'insensitive' } }
      ];
    }
    if (extra.search) {
      where.OR = [
        ...(where.OR || []),
        { appId: { contains: extra.search, mode: 'insensitive' } },
        { name: { contains: extra.search, mode: 'insensitive' } },
        { department: { contains: extra.search, mode: 'insensitive' } },
        { ownerEmail: { contains: extra.search, mode: 'insensitive' } },
        { owner: { name: { contains: extra.search, mode: 'insensitive' } } },
      ];
    }

    const rows = await this.prisma.application.findMany({
      where,
      select: {
        appId: true, name: true, type: true, environment: true,
        department: true, classification: true, criticality: true,
        internetAccessible: true, piiData: true, biaApp: true,
        ownerEmail: true, vaptStatus: true,
        lastVaptDate: true, nextVaptDate: true,
        isActive: true, registeredOn: true,
        owner: { select: { name: true, email: true } },
        securityRequests: {
          where: { deletedAt: null },
          select: {
            vulnerabilities: {
              where: { deletedAt: null },
              select: { severity: true, status: true, slaDueDate: true },
            },
          },
        },
      },
      orderBy: { name: 'asc' },
    });

    return rows.map((a) => {
      const allVulns = a.securityRequests?.flatMap((req) => req.vulnerabilities) || [];
      const openVulnCount = allVulns.filter((v) => v.status !== 'CLOSED').length;
      const critVulnCount = allVulns.filter((v) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
      const vulnsWithSla = allVulns.filter((v) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;

      return {
        'App ID': a.appId,
        Name: a.name,
        Type: a.type,
      Environment: a.environment,
      Department: a.department ?? '',
      Classification: a.classification ?? '',
      Criticality: a.criticality ?? '',
      'Internet Accessible': a.internetAccessible ? 'Yes' : 'No',
      'PII Data': a.piiData ? 'Yes' : 'No',
      'BIA App': a.biaApp ? 'Yes' : 'No',
      'Owner Name': a.owner?.name ?? '',
      'Owner Email': a.ownerEmail ?? '',
      'VAPT Status': a.vaptStatus ?? '',
      'Last VAPT Date': a.lastVaptDate?.toISOString().split('T')[0] ?? '',
      'Next VAPT Date': a.nextVaptDate?.toISOString().split('T')[0] ?? '',
        'Open Vulns': openVulnCount,
        'Critical Vulns': critVulnCount,
        'SLA Compliance %': slaCompliancePct,
        Active: a.isActive ? 'Yes' : 'No',
        'Registered On': a.registeredOn?.toISOString().split('T')[0] ?? '',
      };
    });
  }

  private async fetchInfrastructureAssets(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const where: any = {
      deletedAt: null,
      ...(ctx.environment && { environment: ctx.environment }),
    };

    const extra = ctx.extraFilters || {};
    if (extra.serverId) where.serverId = { contains: extra.serverId, mode: 'insensitive' };
    if (extra.ip) where.ip = { contains: extra.ip, mode: 'insensitive' };
    if (extra.serverName) where.serverName = { contains: extra.serverName, mode: 'insensitive' };
    if (extra.type) where.type = extra.type;
    if (extra.criticality) where.criticality = extra.criticality;
    if (extra.ownerName) {
      where.OR = [
        ...(where.OR || []),
        { assetOwner: { name: { contains: extra.ownerName, mode: 'insensitive' } } },
        { assetOwnerEmail: { contains: extra.ownerName, mode: 'insensitive' } }
      ];
    }
    if (extra.search) {
      where.OR = [
        ...(where.OR || []),
        { serverId: { contains: extra.search, mode: 'insensitive' } },
        { serverName: { contains: extra.search, mode: 'insensitive' } },
        { hostname: { contains: extra.search, mode: 'insensitive' } },
        { ip: { contains: extra.search, mode: 'insensitive' } },
        { assetOwnerEmail: { contains: extra.search, mode: 'insensitive' } },
        { assetOwner: { name: { contains: extra.search, mode: 'insensitive' } } },
      ];
    }

    const rows = await this.prisma.infrastructureAsset.findMany({
      where,
      select: {
        serverId: true, serverName: true, hostname: true, ip: true,
        publicIp: true, type: true, environment: true, location: true,
        os: true, role: true, primaryApp: true, criticality: true,
        assetOwnerEmail: true, appOwnerEmail: true, biaApp: true,
        isActive: true,
        assetOwner: { select: { name: true } },
        securityRequests: {
          where: { deletedAt: null },
          select: {
            vulnerabilities: {
              where: { deletedAt: null },
              select: { severity: true, status: true, slaDueDate: true },
            },
          },
        },
      },
      orderBy: { serverName: 'asc' },
    });

    return rows.map((a) => {
      const allVulns = a.securityRequests?.flatMap((req) => req.vulnerabilities) || [];
      const openVulnCount = allVulns.filter((v) => v.status !== 'CLOSED').length;
      const critVulnCount = allVulns.filter((v) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
      const vulnsWithSla = allVulns.filter((v) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;

      return {
        'Server ID': a.serverId,
        'Server Name': a.serverName,
        Hostname: a.hostname ?? '',
      IP: a.ip ?? '',
      'Public IP': a.publicIp ? 'Yes' : 'No',
      Type: a.type,
      Environment: a.environment,
      Location: a.location ?? '',
      OS: a.os ?? '',
      Role: a.role ?? '',
      'Primary App': a.primaryApp ?? '',
      Criticality: a.criticality ?? '',
      'Asset Owner': a.assetOwner?.name ?? '',
      'Asset Owner Email': a.assetOwnerEmail ?? '',
      'App Owner Email': a.appOwnerEmail ?? '',
      'BIA App': a.biaApp ? 'Yes' : 'No',
        'Open Vulns': openVulnCount,
        'Critical Vulns': critVulnCount,
        'SLA Compliance %': slaCompliancePct,
        Active: a.isActive ? 'Yes' : 'No',
      };
    });
  }

  private async fetchCloudResources(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const where: any = {
      deletedAt: null,
      ...(ctx.environment && { environment: ctx.environment }),
    };

    const extra = ctx.extraFilters || {};
    if (extra.resourceId) where.resourceId = { contains: extra.resourceId, mode: 'insensitive' };
    if (extra.resourceExtId) where.resourceExtId = { contains: extra.resourceExtId, mode: 'insensitive' };
    if (extra.resourceName) where.resourceName = { contains: extra.resourceName, mode: 'insensitive' };
    if (extra.technologyName) where.technologyName = { contains: extra.technologyName, mode: 'insensitive' };
    if (extra.region) where.region = { contains: extra.region, mode: 'insensitive' };
    if (extra.type) where.type = extra.type;
    if (extra.stackLayer) where.stackLayer = extra.stackLayer;
    if (extra.cloudProvider) where.cloudProvider = extra.cloudProvider;
    if (extra.status) where.status = extra.status;
    
    if (extra.cloudAccountId || extra.cloudAccountExtId || extra.cloudAccountProvider) {
      where.cloudAccount = {};
      if (extra.cloudAccountId) where.cloudAccount.accountId = { contains: extra.cloudAccountId, mode: 'insensitive' };
      if (extra.cloudAccountExtId) where.cloudAccount.extId = { contains: extra.cloudAccountExtId, mode: 'insensitive' };
      if (extra.cloudAccountProvider) where.cloudAccount.provider = extra.cloudAccountProvider;
    }

    if (extra.search) {
      where.OR = [
        ...(where.OR || []),
        { resourceId: { contains: extra.search, mode: 'insensitive' } },
        { resourceName: { contains: extra.search, mode: 'insensitive' } },
        { cloudAccount: { accountId: { contains: extra.search, mode: 'insensitive' } } },
      ];
    }

    const rows = await this.prisma.cloudResource.findMany({
      where,
      select: {
        resourceId: true, resourceName: true, resourceExtId: true,
        type: true, cloudProvider: true, technologyName: true,
        stackLayer: true, status: true, region: true, environment: true,
        firstSeen: true, createdAt: true,
        cloudAccount: { select: { accountId: true, extId: true } },
      },
      orderBy: [{ cloudProvider: 'asc' }, { resourceName: 'asc' }],
    });

    return rows.map((r) => ({
      'Resource ID': r.resourceId,
      'Resource Name': r.resourceName,
      'External ID': r.resourceExtId ?? '',
      Type: r.type,
      Provider: r.cloudProvider,
      Technology: r.technologyName ?? '',
      'Stack Layer': r.stackLayer ?? '',
      Status: r.status ?? '',
      Region: r.region ?? '',
      Environment: r.environment,
      'Cloud Account ID': r.cloudAccount?.accountId ?? '',
      'Cloud Account Ext ID': r.cloudAccount?.extId ?? '',
      'First Seen': r.firstSeen?.toISOString().split('T')[0] ?? '',
      'Created At': r.createdAt.toISOString().split('T')[0],
    }));
  }

  private async fetchExecutiveDashboard(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const envFilter = ctx.environment ? { environment: ctx.environment } : {};
    const dateFilter = this.buildDateFilter(ctx, 'createdAt');
    const baseWhere = { deletedAt: null, ...envFilter, ...dateFilter };
    const now = new Date();

    const [
      totalApps, totalInfra, totalCloud,
      totalRequests, totalVulns,
      openVulns, closedVulns,
      critVulns, highVulns,
      activeSlaTotal, activeSlaCompliant,
      breachedSla,
    ] = await this.prisma.$transaction([
      this.prisma.application.count({ where: { deletedAt: null, ...envFilter } }),
      this.prisma.infrastructureAsset.count({ where: { deletedAt: null, ...envFilter } }),
      this.prisma.cloudResource.count({ where: { deletedAt: null, ...envFilter } }),
      this.prisma.securityRequest.count({ where: baseWhere }),
      this.prisma.vulnerability.count({ where: baseWhere }),
      this.prisma.vulnerability.count({ where: { ...baseWhere, status: VulnerabilityStatus.OPEN } }),
      this.prisma.vulnerability.count({ where: { ...baseWhere, status: VulnerabilityStatus.CLOSED } }),
      this.prisma.vulnerability.count({ where: { ...baseWhere, severity: Severity.CRITICAL } }),
      this.prisma.vulnerability.count({ where: { ...baseWhere, severity: Severity.HIGH } }),
      this.prisma.vulnerability.count({
        where: { ...baseWhere, status: { in: [VulnerabilityStatus.OPEN, VulnerabilityStatus.ASSIGNED, VulnerabilityStatus.IN_PROGRESS, VulnerabilityStatus.PATCHED, VulnerabilityStatus.PENDING_REVALIDATION] } },
      }),
      this.prisma.vulnerability.count({
        where: { ...baseWhere, slaDueDate: { gt: now }, status: { in: [VulnerabilityStatus.OPEN, VulnerabilityStatus.ASSIGNED, VulnerabilityStatus.IN_PROGRESS, VulnerabilityStatus.PATCHED, VulnerabilityStatus.PENDING_REVALIDATION] } },
      }),
      this.prisma.vulnerability.count({
        where: { ...baseWhere, slaTracking: { isBreached: true } },
      }),
    ]);

    const compliancePct = activeSlaTotal > 0
      ? Math.round((activeSlaCompliant / activeSlaTotal) * 100)
      : 100;

    return [{
      Metric: 'Executive Dashboard Summary',
      Environment: ctx.environment ?? 'All',
      'Report Period': `${ctx.startDate ?? 'Inception'} → ${ctx.endDate ?? 'Now'}`,
      'Total Applications': totalApps,
      'Total Infrastructure Assets': totalInfra,
      'Total Cloud Resources': totalCloud,
      'Total Security Requests': totalRequests,
      'Total Vulnerabilities': totalVulns,
      'Open Vulnerabilities': openVulns,
      'Closed Vulnerabilities': closedVulns,
      'Critical Vulnerabilities': critVulns,
      'High Vulnerabilities': highVulns,
      'Active SLA Tracked': activeSlaTotal,
      'Within SLA': activeSlaCompliant,
      'SLA Breached': breachedSla,
      'SLA Compliance %': compliancePct,
      'Generated At': now.toISOString(),
    }];
  }

  private async fetchContinuousScanFindings(ctx: GenerationContext): Promise<Record<string, unknown>[]> {
    const where: any = {
      ...this.buildDateFilter(ctx, 'createdAt'),
    };
    if (ctx.severity) where.severity = ctx.severity;
    if (ctx.status) where.status = ctx.status;
    if (ctx.source) where.scannerName = ctx.source;
    if (ctx.assignmentMethod) where.assignmentMethod = ctx.assignmentMethod;
    if (ctx.owner) where.assignedOwnerId = ctx.owner;
    if (ctx.asset) where.assetId = ctx.asset;

    const extra = ctx.extraFilters || {};
    if (extra.id) where.id = { contains: extra.id, mode: 'insensitive' };
    if (extra.vulnTitle) where.vulnTitle = { contains: extra.vulnTitle, mode: 'insensitive' };
    if (extra.owner) where.assignedOwnerName = { contains: extra.owner, mode: 'insensitive' };
    if (extra.asset) where.assetName = { contains: extra.asset, mode: 'insensitive' };

    if (extra.search) {
      where.OR = [
        ...(where.OR || []),
        { id: { contains: extra.search, mode: 'insensitive' } },
        { vulnTitle: { contains: extra.search, mode: 'insensitive' } },
        { assetName: { contains: extra.search, mode: 'insensitive' } },
        { assignedOwnerName: { contains: extra.search, mode: 'insensitive' } },
      ];
    }

    // Fetch findings
    const rows = await this.prisma.continuousScanFinding.findMany({
      where,
      orderBy: { createdAt: 'desc' },
    });

    // If application filter is provided, we need to map assets to applications and filter
    const assetIds = Array.from(new Set(rows.map((r) => r.assetId).filter(Boolean))) as string[];
    let assetMap = new Map<string, string>();
    
    if (assetIds.length > 0) {
      const assets = await this.prisma.infrastructureAsset.findMany({
        where: { id: { in: assetIds } },
        select: { id: true, primaryApp: true },
      });
      assetMap = new Map(assets.map((a) => [a.id, a.primaryApp ?? '']));
    }

    let results = rows.map((r) => ({
      'Finding ID': r.id,
      Source: r.scannerName,
      Severity: r.severity,
      Status: r.status,
      Asset: r.assetName ?? '',
      Application: r.assetId ? (assetMap.get(r.assetId) ?? '') : '',
      'Assigned Owner': r.assignedOwnerName ?? '',
      'Assignment Method': r.assignmentMethod ?? '',
      'Security Request ID': r.securityRequestId ?? '',
      'Vulnerability ID': r.vulnerabilityId ?? '',
      'Created Date': r.createdAt.toISOString().split('T')[0],
      'Accepted Date': r.acceptedAt ? r.acceptedAt.toISOString().split('T')[0] : '',
    }));

    if (ctx.application) {
      const targetApp = ctx.application.toLowerCase();
      results = results.filter((r) => r.Application.toLowerCase().includes(targetApp));
    }

    return results;
  }

  // ── File Writers ────────────────────────────────────────────────────────────

  private async writeFile(
    ctx: GenerationContext,
    rows: Record<string, unknown>[],
  ): Promise<{ storageKey: string; url: string }> {
    if (!fs.existsSync(REPORTS_DIR)) {
      fs.mkdirSync(REPORTS_DIR, { recursive: true });
    }

    const timestamp = Date.now();
    const ext = ctx.format === ReportFormat.XLSX ? 'xlsx' : 'csv';
    const filename = `${ctx.reportId}-${timestamp}.${ext}`;
    const filePath = path.join(REPORTS_DIR, filename);
    const storageKey = `reports/${filename}`;
    const url = `/uploads/reports/${filename}`;

    if (ctx.format === ReportFormat.CSV) {
      await this.writeCsv(filePath, rows);
    } else {
      await this.writeXlsx(filePath, rows, ctx);
    }

    return { storageKey, url };
  }

  private async writeCsv(filePath: string, rows: Record<string, unknown>[]): Promise<void> {
    if (rows.length === 0) {
      fs.writeFileSync(filePath, 'No data found for the selected filters.\n', 'utf8');
      return;
    }

    const csv = CsvBuilder.build(rows);
    fs.writeFileSync(filePath, csv, 'utf8');
  }

  private async writeXlsx(
    filePath: string,
    rows: Record<string, unknown>[],
    ctx: GenerationContext,
  ): Promise<void> {
    if (!ExcelJS) {
      throw new Error(
        'ExcelJS is not installed. Run: npm install exceljs — then retry XLSX generation.',
      );
    }

    const workbook = new ExcelJS.Workbook();
    workbook.creator = 'Sentinel SLM';
    workbook.created = new Date();

    const sheet = workbook.addWorksheet(ctx.type.replace(/_/g, ' '), {
      pageSetup: { orientation: 'landscape' },
    });

    const headers = rows.length > 0 ? Object.keys(rows[0]) : [];

    // Header row — styled
    sheet.addRow(headers);
    const headerRow = sheet.getRow(1);
    headerRow.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    headerRow.fill = {
      type: 'pattern',
      pattern: 'solid',
      fgColor: { argb: 'FF1E3A5F' },
    };
    headerRow.alignment = { vertical: 'middle', horizontal: 'center' };
    headerRow.height = 20;

    // Set column widths
    headers.forEach((h, i) => {
      sheet.getColumn(i + 1).width = Math.max(h.length + 4, 16);
    });

    // Data rows
    for (const row of rows) {
      sheet.addRow(headers.map((h) => row[h] ?? ''));
    }

    // Freeze header
    sheet.views = [{ state: 'frozen', ySplit: 1 }];

    await workbook.xlsx.writeFile(filePath);
  }
}
