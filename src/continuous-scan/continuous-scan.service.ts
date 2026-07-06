import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  AuditAction,
  AuditEntityType,
  CvsAssignmentMethod,
  Environment,
  RequestSource,
  Severity,
  VulnerabilityStatus,
} from '@prisma/client';
import {
  FilterCvsFindingDto,
  CreateCvsFindingDto,
  AssignByAssetDto,
  AcceptFindingDto,
} from './dto/continuous-scan.dto';
import { ComplianceMappingService } from '../compliance/compliance-mapping.service';

// SLA days mirror the SlaPolicy seed values
const SLA_DAYS: Record<Severity, number> = {
  CRITICAL: 30,
  HIGH: 45,
  MEDIUM: 90,
  LOW: 180,
  INFORMATIONAL: 365,
};

@Injectable()
export class ContinuousScanService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly complianceMapping: ComplianceMappingService,
  ) {}

  // ── Helpers ─────────────────────────────────────────────────────────────────

  private computeSlaDue(severity: Severity, base?: Date): Date {
    const from = base ?? new Date();
    const due = new Date(from);
    due.setDate(due.getDate() + SLA_DAYS[severity]);
    return due;
  }

  private buildVulnId(): string {
    const year = new Date().getFullYear();
    const rand = Math.floor(1000 + Math.random() * 9000);
    return `CVS-${year}-${rand}`;
  }

  private buildReqId(): string {
    const year = new Date().getFullYear();
    const rand = Math.floor(1000 + Math.random() * 9000);
    return `CVS-REQ-${year}-${rand}`;
  }

  private async logAudit(
    actorId: string,
    actorName: string,
    action: AuditAction,
    entityType: AuditEntityType,
    entityId: string,
    before?: unknown,
    after?: unknown,
    metadata?: unknown,
  ) {
    await this.prisma.auditLog.create({
      data: {
        actorId,
        actorName,
        entityType,
        entityId,
        action,
        before: before as never,
        after: after as never,
        metadata: metadata as never,
      },
    });
  }

  private async findFindingOrFail(id: string) {
    const finding = await this.prisma.continuousScanFinding.findUnique({
      where: { id },
    });
    if (!finding) throw new NotFoundException(`CVS Finding '${id}' not found.`);
    return finding;
  }

  // ── READ ─────────────────────────────────────────────────────────────────────

  async findAll(filter: FilterCvsFindingDto = {}) {
    const { 
      page = 1, limit = 20, 
      status, severity, source, startDate, endDate, 
      search, id, vulnTitle, asset, owner 
    } = filter;
    
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = {};
    if (status) where.status = status;
    if (severity) where.severity = severity;
    if (source) where.source = source;
    if (id) where.id = id;
    if (vulnTitle) where.vulnTitle = vulnTitle;
    if (asset) where.assetName = { contains: asset, mode: 'insensitive' };
    if (owner) where.assignedOwnerId = owner;
    
    if (startDate || endDate) {
      where.createdAt = {
        ...(startDate && { gte: new Date(startDate) }),
        ...(endDate && { lte: new Date(endDate) }),
      };
    }
    
    if (search) {
      where.OR = [
        { id: { contains: search, mode: 'insensitive' } },
        { vulnTitle: { contains: search, mode: 'insensitive' } },
        { description: { contains: search, mode: 'insensitive' } },
        { assetName: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [data, total] = await Promise.all([
      this.prisma.continuousScanFinding.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.continuousScanFinding.count({ where }),
    ]);
    
    return {
      data,
      pagination: {
        totalItems: total,
        currentPage: page,
        pageSize: limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(id: string) {
    return this.findFindingOrFail(id);
  }

  // ── CREATE (Manual Entry) ─────────────────────────────────────────────────────

  async createManual(
    dto: CreateCvsFindingDto,
    actor: { id: string; name: string },
  ) {
    const slaDueAt = this.computeSlaDue(dto.severity);

    const finding = await this.prisma.continuousScanFinding.create({
      data: {
        scannerName: dto.scannerName ?? 'MANUAL',
        source: 'MANUAL',
        vulnTitle: dto.vulnTitle,
        description: dto.description,
        severity: dto.severity,
        cvss: dto.cvss,
        cve: dto.cve,
        assetId: dto.assetId,
        assetName: dto.assetName,
        status: 'NEW',
        slaDueAt,
      },
    });

    await this.logAudit(
      actor.id, actor.name,
      AuditAction.CREATED,
      AuditEntityType.SCAN_FINDING,
      finding.id,
      null,
      finding,
      { source: 'MANUAL' },
    );

    return finding;
  }

  // ── MARK PATCHED — removed: PATCHED belongs to the Vulnerability lifecycle only ─
  // ContinuousScanFinding lifecycle ends at ACCEPTED.
  // Remediation state is tracked exclusively on the linked Vulnerability.

  // ── ASSIGNMENT HELPERS ───────────────────────────────────────────────────────

  /**
   * Lookup the InfrastructureAsset by the finding's assetId and return
   * the asset owner details. Returns null if asset not found or has no owner.
   */
  private async resolveOwnerFromAsset(assetId: string | null | undefined) {
    if (!assetId) return null;
    const asset = await this.prisma.infrastructureAsset.findFirst({
      where: { id: assetId, isActive: true },
      select: {
        id: true,
        assetOwnerId: true,
        assetOwner: { select: { id: true, name: true } },
      },
    });
    if (!asset?.assetOwner) return null;
    return { ownerId: asset.assetOwner.id, ownerName: asset.assetOwner.name };
  }

  private async applyAssignment(
    findingId: string,
    ownerId: string,
    ownerName: string,
    method: CvsAssignmentMethod,
  ) {
    return this.prisma.continuousScanFinding.update({
      where: { id: findingId },
      data: {
        assignedOwnerId: ownerId,
        assignedOwnerName: ownerName,
        assignmentMethod: method,
        assignedAt: new Date(),
        status: 'ASSIGNED',
      },
    });
  }

  // ── AUTO ASSIGN (single finding) ─────────────────────────────────────────────

  /**
   * POST /continuous-scan/:id/auto-assign
   * Looks up the asset owner for the finding's assetId and assigns automatically.
   * Returns the updated finding. If no owner is found, returns the finding unchanged.
   */
  async autoAssign(
    id: string,
    actor: { id: string; name: string },
  ) {
    const finding = await this.findFindingOrFail(id);

    if (finding.status === 'ACCEPTED') {
      throw new ConflictException('Finding has already been accepted and cannot be re-assigned.');
    }

    const owner = await this.resolveOwnerFromAsset(finding.assetId);
    if (!owner) {
      return { finding, assigned: false, reason: 'No asset or no asset owner found.' };
    }

    const updated = await this.applyAssignment(id, owner.ownerId, owner.ownerName, CvsAssignmentMethod.AUTO);

    await this.logAudit(
      actor.id, actor.name,
      AuditAction.ASSIGNED,
      AuditEntityType.SCAN_FINDING,
      id,
      { status: finding.status },
      { assignedOwnerId: owner.ownerId, assignedOwnerName: owner.ownerName, method: 'AUTO' },
    );

    return { finding: updated, assigned: true };
  }

  // ── ASSIGN BY ASSET ───────────────────────────────────────────────────────────

  /**
   * POST /continuous-scan/assign-by-asset
   * Assigns all (or selected) unassigned findings for a given asset to the asset owner.
   */
  async assignByAsset(
    dto: AssignByAssetDto,
    actor: { id: string; name: string },
  ) {
    // Lookup the asset + owner
    const asset = await this.prisma.infrastructureAsset.findFirst({
      where: { id: dto.assetId, isActive: true },
      select: {
        id: true,
        serverName: true,
        assetOwner: { select: { id: true, name: true } },
      },
    });

    if (!asset) {
      throw new NotFoundException(`Infrastructure asset '${dto.assetId}' not found.`);
    }
    if (!asset.assetOwner) {
      return { assigned: 0, skipped: 0, reason: `Asset '${asset.serverName}' has no registered owner.` };
    }

    // Find unassigned findings for this asset
    const where: Record<string, unknown> = {
      assetId: dto.assetId,
      status: 'NEW',
    };
    if (dto.findingIds?.length) {
      where.id = { in: dto.findingIds };
    }

    const findings = await this.prisma.continuousScanFinding.findMany({ where });

    if (findings.length === 0) {
      return { assigned: 0, skipped: 0, reason: 'No unassigned findings found for this asset.' };
    }

    // Bulk update
    const now = new Date();
    await this.prisma.continuousScanFinding.updateMany({
      where: { id: { in: findings.map((f) => f.id) } },
      data: {
        assignedOwnerId: asset.assetOwner.id,
        assignedOwnerName: asset.assetOwner.name,
        assignmentMethod: CvsAssignmentMethod.ASSET,
        assignedAt: now,
        status: 'ASSIGNED',
      },
    });

    await this.logAudit(
      actor.id, actor.name,
      AuditAction.ASSIGNED,
      AuditEntityType.SCAN_FINDING,
      dto.assetId,
      null,
      { findingCount: findings.length, assetOwner: asset.assetOwner.name, method: 'ASSET' },
    );

    return {
      assigned: findings.length,
      skipped: 0,
      assetName: asset.serverName,
      ownerName: asset.assetOwner.name,
    };
  }

  // ── ASSIGN ALL TO OWNERS ──────────────────────────────────────────────────────

  /**
   * POST /continuous-scan/assign-all
   * For every NEW (unassigned) finding, looks up the asset owner and assigns it.
   * Returns counts: assigned, skipped (no owner), total processed.
   */
  async assignAll(actor: { id: string; name: string }) {
    const unassigned = await this.prisma.continuousScanFinding.findMany({
      where: { status: 'NEW' },
    });

    let assigned = 0;
    let skipped = 0;
    const now = new Date();

    for (const finding of unassigned) {
      const owner = await this.resolveOwnerFromAsset(finding.assetId);
      if (!owner) {
        skipped++;
        continue;
      }

      await this.prisma.continuousScanFinding.update({
        where: { id: finding.id },
        data: {
          assignedOwnerId: owner.ownerId,
          assignedOwnerName: owner.ownerName,
          assignmentMethod: CvsAssignmentMethod.AUTO,
          assignedAt: now,
          status: 'ASSIGNED',
        },
      });
      assigned++;
    }

    await this.logAudit(
      actor.id, actor.name,
      AuditAction.UPDATED,
      AuditEntityType.SCAN_FINDING,
      'bulk',
      null,
      { totalProcessed: unassigned.length, assigned, skipped, method: 'AUTO' },
    );

    return {
      totalProcessed: unassigned.length,
      assigned,
      skipped,
    };
  }

  // ── ACCEPT (Promote to SecurityRequest + Vulnerability) ──────────────────────

  /**
   * POST /continuous-scan/:id/accept
   *
   * When a security analyst accepts a CVS finding:
   * 1. Creates a SecurityRequest (source = CVS).
   * 2. Creates a Vulnerability linked to that SecurityRequest.
   * 3. Creates an SlaTracking record.
   * 4. Creates a VulnerabilityLifecycleLog entry.
   * 5. Updates the ContinuousScanFinding with downstream linkage.
   * 6. Creates an AuditLog entry.
   *
   * All 6 operations are wrapped in a single Prisma $transaction.
   */
  async acceptFinding(
    id: string,
    dto: AcceptFindingDto,
    actor: { id: string; name: string; role: string },
  ) {
    const finding = await this.findFindingOrFail(id);

    if (finding.status === 'ACCEPTED') {
      throw new ConflictException('Finding has already been accepted.');
    }

    // Guard: owner must be assigned before a finding can be accepted.
    // This enforces the lifecycle: NEW → ASSIGNED → ACCEPTED.
    if (!finding.assignedOwnerId) {
      throw new BadRequestException(
        'Please assign an owner before accepting this finding.',
      );
    }

    const now = new Date();
    const reqId = this.buildReqId();
    const vulnId = this.buildVulnId();
    const slaDueDate = this.computeSlaDue(finding.severity, now);

    const result = await this.prisma.$transaction(async (tx) => {
      // ── 1. Create SecurityRequest ──────────────────────────────────────────
      const securityRequest = await tx.securityRequest.create({
        data: {
          reqId,
          source: RequestSource.CVS,
          environment: Environment.PRODUCTION,
          status: 'OPEN',
          initiatedById: actor.id,
          // If the finding has an asset link, attach to infra
          targetInfraId: finding.assetId ?? undefined,
          assessmentMeta: {
            cvsFindingId: finding.id,
            scannerName: finding.scannerName,
            source: finding.source,
          } as never,
        },
      });

      // ── 2. Create Vulnerability ────────────────────────────────────────────
      const vulnerability = await tx.vulnerability.create({
        data: {
          vulnId,
          requestId: securityRequest.id,
          source: RequestSource.CVS,
          environment: Environment.PRODUCTION,
          type: finding.vulnTitle,
          shortDesc: finding.vulnTitle,
          description: finding.description ?? undefined,
          severity: finding.severity,
          cvss: finding.cvss ?? undefined,
          cve: finding.cve ?? undefined,
          externalId: finding.id,   // backlink to the CVS finding
          reportedBy: actor.name,
          reportedOn: now,
          slaDueDate,
          assignedToId: dto.assignedToId ?? undefined,
          poc: dto.notes ?? undefined,
        },
      });

      // ── 3. Create SlaTracking ──────────────────────────────────────────────
      await tx.slaTracking.create({
        data: {
          vulnerabilityId: vulnerability.id,
          dueDate: slaDueDate,
          daysRemaining: SLA_DAYS[finding.severity],
        },
      });

      // ── 4. Create VulnerabilityLifecycleLog ───────────────────────────────
      await tx.vulnerabilityLifecycleLog.create({
        data: {
          vulnerabilityId: vulnerability.id,
          fromStatus: null,
          toStatus: VulnerabilityStatus.OPEN,
          actorId: actor.id,
          actorName: actor.name,
          actorRole: actor.role,
          remarks: `Created from CVS finding ${finding.id} via Accept action`,
        },
      });

      // ── 5. Update ContinuousScanFinding with downstream linkage ───────────
      const updatedFinding = await tx.continuousScanFinding.update({
        where: { id },
        data: {
          status: 'ACCEPTED',
          acceptedAt: now,
          securityRequestId: securityRequest.id,
          vulnerabilityId: vulnerability.id,
        },
      });

      return { securityRequest, vulnerability, finding: updatedFinding };
    });

    // ── 6. AuditLog (outside transaction — non-critical) ──────────────────────
    await this.logAudit(
      actor.id, actor.name,
      AuditAction.STATUS_CHANGED,
      AuditEntityType.SCAN_FINDING,
      id,
      { status: 'ASSIGNED' },
      {
        status: 'ACCEPTED',
        securityRequestId: result.securityRequest.id,
        securityRequestReqId: result.securityRequest.reqId,
        vulnerabilityId: result.vulnerability.id,
        vulnerabilityVulnId: result.vulnerability.vulnId,
      },
    );

    // ── 7. Auto-map to Security Controls (fire-and-forget) ────────────────────
    void this.complianceMapping.mapVulnerability(
      result.vulnerability.id,
      result.vulnerability.type,
    );

    return {
      finding: result.finding,
      securityRequest: {
        id: result.securityRequest.id,
        reqId: result.securityRequest.reqId,
      },
      vulnerability: {
        id: result.vulnerability.id,
        vulnId: result.vulnerability.vulnId,
        severity: result.vulnerability.severity,
        status: result.vulnerability.status,
        slaDueDate,
      },
    };
  }
}
