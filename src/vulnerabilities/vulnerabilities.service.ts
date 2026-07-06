import {
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { VulnerabilityWorkflowValidator } from './workflow/vulnerability-workflow.validator';
import {
  CreateVulnerabilityDto,
  UpdateVulnerabilityDto,
  UpdateVulnerabilityStatusDto,
  AddVulnCommentDto,
  FilterVulnerabilityDto,
} from './dto/vulnerability.dto';
import { NotificationsService } from '../notifications/notifications.service';
import { ComplianceMappingService } from '../compliance/compliance-mapping.service';
import {
  AuditAction, AuditEntityType, Severity, VulnerabilityStatus,
} from '@prisma/client';
import * as path from 'path';
import * as fs from 'fs';

// ── SLA days per severity (mirrors SlaPolicy seed) ───────────────────────────
const SLA_DAYS: Record<Severity, number> = {
  CRITICAL: 30,
  HIGH: 45,
  MEDIUM: 90,
  LOW: 180,
  INFORMATIONAL: 365,
};

const UPLOAD_DIR = path.join(process.cwd(), 'uploads', 'vulnerabilities');
const MAX_BYTES = 20 * 1024 * 1024;
const ALLOWED_MIME = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'image/png', 'image/jpeg', 'text/plain', 'text/csv',
];

// ── Select shape ──────────────────────────────────────────────────────────────
const VULN_SELECT = {
  id: true, vulnId: true, requestId: true, source: true, environment: true,
  type: true, shortDesc: true, description: true, severity: true,
  cvss: true, cve: true, affectedComponent: true, references: true,
  status: true, pendingWith: true, assignedToId: true,
  exploitAvail: true, exploitConf: true,
  poc: true, remediation: true, impact: true,
  reportedBy: true, reportedOn: true, slaDueDate: true,
  externalId: true, closedAt: true, createdAt: true, updatedAt: true,
  request: { 
    select: { 
      id: true, reqId: true, source: true,
      targetApp: { select: { name: true, owner: { select: { email: true } } } },
      targetInfra: { select: { serverName: true, assetOwner: { select: { email: true } } } },
    } 
  },
  assignedTo: { select: { id: true, name: true, email: true } },
  slaTracking: { select: { dueDate: true, isBreached: true, daysRemaining: true } },
  _count: { select: { comments: true, attachments: true, lifecycleLogs: true } },
} as const;

@Injectable()
export class VulnerabilitiesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly workflow: VulnerabilityWorkflowValidator,
    private readonly notifications: NotificationsService,
    private readonly complianceMapping: ComplianceMappingService,
  ) {}

  // ── Helpers ─────────────────────────────────────────────────────────────────

  private async findOrFail(id: string) {
    const v = await this.prisma.vulnerability.findFirst({
      where: { id, deletedAt: null },
      select: VULN_SELECT,
    });
    if (!v) throw new NotFoundException(`Vulnerability '${id}' not found.`);
    return v;
  }

  private computeSlaDue(severity: Severity, reportedOn?: Date): Date {
    const base = reportedOn ?? new Date();
    const due = new Date(base);
    due.setDate(due.getDate() + SLA_DAYS[severity]);
    return due;
  }

  private buildVulnId(requestId: string, source: string): string {
    const prefix: Record<string, string> = {
      VAPT: 'VAPT', BUG_BOUNTY: 'BB', RED_TEAM: 'RT', CLOUDSEK: 'CSEK', CVS: 'CVS',
    };
    const year = new Date().getFullYear();
    const rand = Math.floor(1000 + Math.random() * 9000);
    return `${prefix[source] ?? 'VLN'}-${year}-${rand}`;
  }

  private async logAudit(
    actorId: string, actorName: string, action: AuditAction,
    entityId: string, before?: unknown, after?: unknown,
  ) {
    await this.prisma.auditLog.create({
      data: {
        actorId, actorName,
        entityType: AuditEntityType.VULNERABILITY,
        entityId, action,
        before: before as never,
        after: after as never,
      },
    });
  }

  private async createLifecycleLog(
    vulnerabilityId: string,
    fromStatus: VulnerabilityStatus | null,
    toStatus: VulnerabilityStatus,
    actor: { id: string; name: string; role: string },
    remarks?: string,
  ) {
    await this.prisma.vulnerabilityLifecycleLog.create({
      data: {
        vulnerabilityId,
        fromStatus: fromStatus ?? undefined,
        toStatus,
        actorId: actor.id,
        actorName: actor.name,
        actorRole: actor.role,
        remarks,
      },
    });
  }

  // ── CRUD ─────────────────────────────────────────────────────────────────────

  async findAll(filter: FilterVulnerabilityDto) {
    const {
      page = 1, limit = 20, environment, source, severity,
      status, requestId, assignedToId, startDate, endDate, breached, search,
    } = filter;
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = { deletedAt: null };
    if (environment) where.environment = environment;
    if (source) where.source = source;
    if (severity) where.severity = severity;
    if (status) where.status = status;
    if (requestId) where.requestId = requestId;
    if (assignedToId) where.assignedToId = assignedToId;
    if (startDate || endDate) {
      where.createdAt = {
        ...(startDate && { gte: new Date(startDate) }),
        ...(endDate && { lte: new Date(endDate) }),
      };
    }
    if (breached === 'true') {
      where.slaTracking = { isBreached: true };
    }
    if (search) {
      where.OR = [
        { vulnId:           { contains: search, mode: 'insensitive' } },
        { shortDesc:        { contains: search, mode: 'insensitive' } },
        { type:             { contains: search, mode: 'insensitive' } },
        { affectedComponent:{ contains: search, mode: 'insensitive' } },
      ];
    }

    const [
      data,
      total,
      open,
      critical,
      high,
      medium,
      low,
      patched,
      pendingRevalidation,
      closed
    ] = await this.prisma.$transaction([
      this.prisma.vulnerability.findMany({
        where, select: VULN_SELECT,
        orderBy: { createdAt: 'desc' },
        skip, take: limit,
      }),
      this.prisma.vulnerability.count({ where }),
      this.prisma.vulnerability.count({ where: { ...where, status: { notIn: [VulnerabilityStatus.PATCHED, VulnerabilityStatus.CLOSED] } } }),
      this.prisma.vulnerability.count({ where: { ...where, severity: Severity.CRITICAL } }),
      this.prisma.vulnerability.count({ where: { ...where, severity: Severity.HIGH } }),
      this.prisma.vulnerability.count({ where: { ...where, severity: Severity.MEDIUM } }),
      this.prisma.vulnerability.count({ where: { ...where, severity: Severity.LOW } }),
      this.prisma.vulnerability.count({ where: { ...where, status: VulnerabilityStatus.PATCHED } }),
      this.prisma.vulnerability.count({ where: { ...where, status: VulnerabilityStatus.PENDING_REVALIDATION } }),
      this.prisma.vulnerability.count({ where: { ...where, status: VulnerabilityStatus.CLOSED } }),
    ]);

    return { 
      data, 
      total, 
      page, 
      limit, 
      totalPages: Math.ceil(total / limit),
      summary: {
        total,
        open,
        critical,
        high,
        medium,
        low,
        patched,
        pendingRevalidation,
        closed
      }
    };
  }

  async findOne(id: string) {
    return this.findOrFail(id);
  }

  async create(dto: CreateVulnerabilityDto, actor: { id: string; name: string; role: string }) {
    // Verify request exists
    const request = await this.prisma.securityRequest.findFirst({
      where: { id: dto.requestId, deletedAt: null },
    });
    if (!request) throw new BadRequestException(`SecurityRequest '${dto.requestId}' not found.`);

    const reportedOn = dto.reportedOn ? new Date(dto.reportedOn) : new Date();
    const slaDueDate = this.computeSlaDue(dto.severity, reportedOn);
    const vulnId = this.buildVulnId(dto.requestId, dto.source);

    const created = await this.prisma.vulnerability.create({
      data: {
        vulnId,
        requestId: dto.requestId,
        source: dto.source,
        environment: dto.environment,
        type: dto.type,
        shortDesc: dto.shortDesc,
        description: dto.description,
        severity: dto.severity,
        cvss: dto.cvss,
        cve: dto.cve,
        affectedComponent: dto.affectedComponent,
        references: dto.references ?? [],
        poc: dto.poc,
        remediation: dto.remediation,
        impact: dto.impact,
        reportedBy: dto.reportedBy,
        reportedOn,
        assignedToId: dto.assignedToId,
        exploitAvail: dto.exploitAvail,
        exploitConf: dto.exploitConf,
        externalId: dto.externalId,
        slaDueDate,
      },
      select: VULN_SELECT,
    });

    // Create SLA tracking record
    await this.prisma.slaTracking.create({
      data: {
        vulnerabilityId: created.id,
        dueDate: slaDueDate,
        daysRemaining: SLA_DAYS[dto.severity],
      },
    });

    // Initial lifecycle log
    await this.createLifecycleLog(
      created.id, null, VulnerabilityStatus.OPEN, actor, 'Vulnerability created',
    );

    await this.logAudit(actor.id, actor.name, AuditAction.CREATED, created.id, null, created);

    // Dispatch Notification
    this.notifications.sendVulnerabilityCreated(created as unknown as Parameters<typeof this.notifications.sendVulnerabilityCreated>[0]);

    // ── Auto-map to Security Controls (fire-and-forget, never blocks response) ──
    void this.complianceMapping.mapVulnerability(created.id, created.type);

    return created;
  }

  async update(id: string, dto: UpdateVulnerabilityDto, actor: { id: string; name: string; role: string }) {
    const existing = await this.findOrFail(id);

    // Recalculate SLA if severity changes
    let slaDueDate: Date | undefined;
    if (dto.severity && dto.severity !== existing.severity) {
      const base = (existing.reportedOn as Date | null) ?? new Date();
      slaDueDate = this.computeSlaDue(dto.severity, base);
    }

    const updated = await this.prisma.vulnerability.update({
      where: { id },
      data: {
        ...(dto.type && { type: dto.type }),
        ...(dto.shortDesc && { shortDesc: dto.shortDesc }),
        ...(dto.description !== undefined && { description: dto.description }),
        ...(dto.severity && { severity: dto.severity }),
        ...(dto.cvss !== undefined && { cvss: dto.cvss }),
        ...(dto.cve !== undefined && { cve: dto.cve }),
        ...(dto.affectedComponent !== undefined && { affectedComponent: dto.affectedComponent }),
        ...(dto.references && { references: dto.references }),
        ...(dto.poc !== undefined && { poc: dto.poc }),
        ...(dto.remediation !== undefined && { remediation: dto.remediation }),
        ...(dto.impact !== undefined && { impact: dto.impact }),
        ...(dto.assignedToId !== undefined && { assignedToId: dto.assignedToId }),
        ...(dto.pendingWith !== undefined && { pendingWith: dto.pendingWith }),
        ...(dto.exploitAvail !== undefined && { exploitAvail: dto.exploitAvail }),
        ...(dto.exploitConf !== undefined && { exploitConf: dto.exploitConf }),
        ...(dto.externalId !== undefined && { externalId: dto.externalId }),
        ...(slaDueDate && { slaDueDate }),
      },
      select: VULN_SELECT,
    });

    // Update SLA tracking if severity changed
    if (slaDueDate) {
      await this.prisma.slaTracking.updateMany({
        where: { vulnerabilityId: id },
        data: { dueDate: slaDueDate },
      });
    }

    const action = dto.assignedToId && dto.assignedToId !== existing.assignedToId
      ? AuditAction.ASSIGNED
      : AuditAction.UPDATED;

    await this.logAudit(actor.id, actor.name, action, id, existing, updated);

    // Dispatch Assignment Notification
    if (dto.assignedToId && dto.assignedToId !== existing.assignedToId) {
      this.notifications.sendAssignment(updated as unknown as Parameters<typeof this.notifications.sendAssignment>[0]);
    }

    return updated;
  }

  async updateStatus(
    id: string,
    dto: UpdateVulnerabilityStatusDto,
    actor: { id: string; name: string; role: string },
  ) {
    const existing = await this.findOrFail(id);

    this.workflow.validate(existing.status, dto.status);

    const timestamps: Record<string, Date> = {};
    if (dto.status === VulnerabilityStatus.CLOSED) timestamps.closedAt = new Date();

    const updated = await this.prisma.vulnerability.update({
      where: { id },
      data: {
        status: dto.status,
        ...(dto.pendingWith !== undefined && { pendingWith: dto.pendingWith }),
        ...timestamps,
      },
      select: VULN_SELECT,
    });

    // Lifecycle log
    await this.createLifecycleLog(
      id, existing.status, dto.status, actor, dto.remarks,
    );

    // Mark SLA breached when closing if past due
    if (dto.status === VulnerabilityStatus.CLOSED && existing.slaDueDate) {
      const isBreached = new Date() > (existing.slaDueDate as Date);
      await this.prisma.slaTracking.updateMany({
        where: { vulnerabilityId: id },
        data: { isBreached, ...(isBreached && { breachedAt: new Date() }) },
      });
    }

    await this.logAudit(
      actor.id, actor.name, AuditAction.STATUS_CHANGED, id,
      { status: existing.status },
      { status: dto.status, remarks: dto.remarks },
    );

    // ── Dispatch Status Notifications ──────────────────────────────────────────
    if (dto.status === VulnerabilityStatus.PENDING_REVALIDATION) {
      // Find a security lead to notify
      const secLead = await this.prisma.user.findFirst({ where: { role: 'SECURITY_LEAD', deletedAt: null } });
      if (secLead) {
        this.notifications.sendRevalidationSubmitted(updated as unknown as Parameters<typeof this.notifications.sendRevalidationSubmitted>[0], secLead.email);
      }
    } else if (dto.status === VulnerabilityStatus.IN_PROGRESS && existing.status === VulnerabilityStatus.PENDING_REVALIDATION) {
      // It was in revalidation, and now pushed back to in progress -> Revalidation Failed
      this.notifications.sendRevalidationFailed(updated as unknown as Parameters<typeof this.notifications.sendRevalidationFailed>[0]);
    } else if (dto.status === VulnerabilityStatus.CLOSED) {
      this.notifications.sendVulnerabilityClosed(updated as unknown as Parameters<typeof this.notifications.sendVulnerabilityClosed>[0]);
    }

    return updated;
  }

  async remove(id: string, actor: { id: string; name: string }) {
    await this.findOrFail(id);
    await this.prisma.vulnerability.update({
      where: { id },
      data: { deletedAt: new Date() },
    });
    await this.logAudit(actor.id, actor.name, AuditAction.DELETED, id);
    return { message: 'Vulnerability deleted.' };
  }

  // ── Comments ────────────────────────────────────────────────────────────────

  async getComments(vulnId: string) {
    await this.findOrFail(vulnId);
    return this.prisma.comment.findMany({
      where: { vulnerabilityId: vulnId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true, body: true, authorName: true, authorRole: true,
        createdAt: true, updatedAt: true,
        author: { select: { id: true, name: true, email: true } },
      },
    });
  }

  async addComment(
    vulnId: string,
    dto: AddVulnCommentDto,
    actor: { id: string; name: string; role: string },
  ) {
    await this.findOrFail(vulnId);
    const comment = await this.prisma.comment.create({
      data: {
        vulnerabilityId: vulnId,
        authorId: actor.id,
        authorName: actor.name,
        authorRole: actor.role,
        body: dto.body,
      },
      select: { id: true, body: true, authorName: true, authorRole: true, createdAt: true },
    });
    await this.logAudit(actor.id, actor.name, AuditAction.COMMENTED, vulnId, null, { commentId: comment.id });
    return comment;
  }

  // ── Attachments ─────────────────────────────────────────────────────────────

  async getAttachments(vulnId: string) {
    await this.findOrFail(vulnId);
    return this.prisma.attachment.findMany({
      where: { vulnerabilityId: vulnId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, filename: true, mimeType: true, sizeBytes: true,
        url: true, uploadedByName: true, createdAt: true,
      },
    });
  }

  async uploadAttachment(
    vulnId: string,
    file: Express.Multer.File,
    actor: { id: string; name: string },
  ) {
    await this.findOrFail(vulnId);

    if (file.size > MAX_BYTES)
      throw new BadRequestException('File exceeds the 20 MB limit.');
    if (!ALLOWED_MIME.includes(file.mimetype))
      throw new BadRequestException(`File type '${file.mimetype}' is not permitted.`);

    if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    const storageKey = `${vulnId}/${Date.now()}-${file.originalname}`;
    const destPath = path.join(UPLOAD_DIR, storageKey.replace('/', path.sep));
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.writeFileSync(destPath, file.buffer);

    const attachment = await this.prisma.attachment.create({
      data: {
        vulnerabilityId: vulnId,
        uploadedById: actor.id,
        uploadedByName: actor.name,
        filename: file.originalname,
        mimeType: file.mimetype,
        sizeBytes: file.size,
        storageKey,
        url: `/uploads/vulnerabilities/${storageKey}`,
      },
      select: { id: true, filename: true, mimeType: true, sizeBytes: true, url: true, createdAt: true },
    });

    await this.logAudit(actor.id, actor.name, AuditAction.ATTACHED, vulnId, null, { attachmentId: attachment.id });
    return attachment;
  }

  // ── Lifecycle Logs ──────────────────────────────────────────────────────────

  async getLifecycleLogs(vulnId: string) {
    await this.findOrFail(vulnId);
    return this.prisma.vulnerabilityLifecycleLog.findMany({
      where: { vulnerabilityId: vulnId },
      orderBy: { timestamp: 'asc' },
      select: {
        id: true, fromStatus: true, toStatus: true,
        actorName: true, actorRole: true, remarks: true, timestamp: true,
      },
    });
  }
}
