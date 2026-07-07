import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { RequestWorkflowValidator } from './workflow/request-workflow.validator';
import {
  CreateSecurityRequestDto,
  UpdateSecurityRequestDto,
  UpdateRequestStatusDto,
  AddCommentDto,
  FilterSecurityRequestDto,
} from './dto/security-request.dto';
import { AuditAction, AuditEntityType, UserRole } from '@prisma/client';
import * as path from 'path';
import * as fs from 'fs';

const UPLOAD_DIR = path.join(process.cwd(), 'uploads', 'security-requests');
const MAX_SIZE_BYTES = 20 * 1024 * 1024; // 20 MB
const ALLOWED_MIME = [
  'application/pdf',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.ms-excel',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'image/png',
  'image/jpeg',
  'text/plain',
  'text/csv',
];

// ── Select shape ──────────────────────────────────────────────────────────────
const REQUEST_SELECT = {
  id: true, reqId: true, source: true, environment: true, status: true,
  targetAppId: true, targetInfraId: true, partner: true, programmeUrl: true,
  initiatedById: true, assignedToId: true, initiatedOn: true,
  submittedAt: true, startedAt: true, findingsSharedAt: true, closedAt: true,
  totalFindings: true, openFindings: true, critFindings: true,
  highFindings: true, slaCompliance: true, assessmentMeta: true,
  createdAt: true, updatedAt: true,
  targetApp: { select: { id: true, appId: true, name: true, prodUrl: true, preprodUrl: true, environment: true } },
  targetInfra: { select: { id: true, serverId: true, serverName: true, hostname: true, ip: true, environment: true } },
  initiatedBy: { select: { id: true, name: true, email: true, role: true } },
  assignedTo: { select: { id: true, name: true, email: true, role: true } },
  vulnerabilities: {
    where: { deletedAt: null },
    orderBy: { createdAt: 'desc' as const },
    select: {
      id: true, vulnId: true, source: true, type: true, shortDesc: true, description: true,
      severity: true, cvss: true, cve: true, affectedComponent: true, references: true,
      status: true, pendingWith: true, reportedBy: true, reportedOn: true, slaDueDate: true,
      poc: true, remediation: true, impact: true, exploitAvail: true, exploitConf: true,
      externalId: true,
      slaTracking: { select: { dueDate: true, isBreached: true, daysRemaining: true } },
    },
  },
  findings: {
    orderBy: { createdAt: 'desc' as const },
    select: {
      id: true, findingId: true, title: true, description: true,
      severity: true, status: true, sourceType: true, cvssScore: true,
      cveId: true, recommendation: true, evidence: true, convertedToVulnerability: true,
      createdAt: true, updatedAt: true,
      vulnerability: { select: { id: true, vulnId: true, status: true } },
    }
  },
  comments: {
    orderBy: { createdAt: 'asc' as const },
    select: {
      id: true, body: true, authorName: true, authorRole: true, createdAt: true,
      author: { select: { id: true, name: true, email: true } },
    },
  },
  attachments: {
    orderBy: { createdAt: 'desc' as const },
    select: { id: true, filename: true, mimeType: true, sizeBytes: true, url: true, uploadedByName: true, createdAt: true },
  },
  _count: { select: { vulnerabilities: true, comments: true, attachments: true } },
} as const;


@Injectable()
export class SecurityRequestsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly workflow: RequestWorkflowValidator,
  ) { }

  // ── Helpers ─────────────────────────────────────────────────────────────────

  private async findOrFail(id: string) {
    const req = await this.prisma.securityRequest.findFirst({
      where: {
        deletedAt: null,
        OR: [{ id }, { reqId: id }],   // accept UUID (internal nav) OR reqId (readable URL nav)
      },
      select: REQUEST_SELECT,
    });
    if (!req) throw new NotFoundException(`Security request '${id}' not found.`);
    return req;
  }

  private async logAudit(
    actorId: string,
    actorName: string,
    action: AuditAction,
    entityId: string,
    before?: unknown,
    after?: unknown,
    metadata?: unknown,
  ) {
    await this.prisma.auditLog.create({
      data: {
        actorId,
        actorName,
        entityType: AuditEntityType.SECURITY_REQUEST,
        entityId,
        action,
        before: before as never,
        after: after as never,
        metadata: metadata as never,
      },
    });
  }

  private buildReqId(source: string): string {
    const prefix: Record<string, string> = {
      VAPT: 'VAPT',
      BUG_BOUNTY: 'BB',
      RED_TEAM: 'RT',
      CLOUDSEK: 'CSEK',
    };
    const year = new Date().getFullYear();
    const rand = Math.floor(1000 + Math.random() * 9000);
    return `${prefix[source] ?? 'REQ'}-${year}-${rand}`;
  }

  // ── CRUD ─────────────────────────────────────────────────────────────────────

  async findAll(filter: FilterSecurityRequestDto, userId?: string) {
    const { 
      page = 1, limit = 20, environment, source, status, targetAppId, targetInfraId, 
      reqId, appName, initiatedBy, assignedTo,
      startDate, endDate, search, sortBy, sortDir
    } = filter;
    const skip = (page - 1) * limit;

    const where: any = {
      deletedAt: null,
      ...(environment && { environment }),
      ...(source && { source }),
      ...(status && { status }),
      ...(targetAppId && { targetAppId }),
      ...(targetInfraId && { targetInfraId }),
      ...(reqId && { reqId: { contains: reqId, mode: 'insensitive' } }),
      ...(appName && { targetApp: { name: { contains: appName, mode: 'insensitive' } } }),
      ...(initiatedBy && { initiatedBy: { name: { contains: initiatedBy, mode: 'insensitive' } } }),
      ...(assignedTo && { assignedTo: { name: { contains: assignedTo, mode: 'insensitive' } } }),
      ...(startDate || endDate
        ? {
          initiatedOn: {
            ...(startDate && { gte: new Date(startDate) }),
            ...(endDate && { lte: new Date(endDate) }),
          },
        }
        : {}),
    };

    if (search) {
      where.OR = [
        { reqId: { contains: search, mode: 'insensitive' } },
        { targetApp: { name: { contains: search, mode: 'insensitive' } } },
        { targetInfra: { serverName: { contains: search, mode: 'insensitive' } } },
        { initiatedBy: { name: { contains: search, mode: 'insensitive' } } },
        { assignedTo: { name: { contains: search, mode: 'insensitive' } } },
      ];
    }

    let orderBy: any = { initiatedOn: 'desc' };
    if (sortBy === 'vulnCount') {
      orderBy = { vulnerabilities: { _count: sortDir || 'desc' } };
    } else if (sortBy === 'initiatedOn') {
      orderBy = { initiatedOn: sortDir || 'desc' };
    }

    const [data, total] = await this.prisma.$transaction([
      this.prisma.securityRequest.findMany({
        where,
        select: REQUEST_SELECT,
        orderBy,
        skip,
        take: limit,
      }),
      this.prisma.securityRequest.count({ where }),
    ]);

    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async findOne(id: string) {
    return this.findOrFail(id);
  }

  async create(dto: CreateSecurityRequestDto, actor: { id: string; name: string }) {
    const reqId = this.buildReqId(dto.source);

    const created = await this.prisma.securityRequest.create({
      data: {
        reqId,
        source: dto.source,
        environment: dto.environment,
        targetAppId: dto.targetAppId,
        targetInfraId: dto.targetInfraId,
        partner: dto.partner,
        programmeUrl: dto.programmeUrl,
        initiatedById: actor.id,
        assignedToId: dto.assignedToId,
        assessmentMeta: dto.assessmentMeta as never,
      },
      select: REQUEST_SELECT,
    });

    await this.logAudit(actor.id, actor.name, AuditAction.CREATED, created.id, null, created);
    return created;
  }

  async update(id: string, dto: UpdateSecurityRequestDto, actor: { id: string; name: string }) {
    const existing = await this.findOrFail(id);

    const updated = await this.prisma.securityRequest.update({
      where: { id },
      data: {
        ...(dto.environment && { environment: dto.environment }),
        ...(dto.targetAppId !== undefined && { targetAppId: dto.targetAppId }),
        ...(dto.targetInfraId !== undefined && { targetInfraId: dto.targetInfraId }),
        ...(dto.partner !== undefined && { partner: dto.partner }),
        ...(dto.programmeUrl !== undefined && { programmeUrl: dto.programmeUrl }),
        ...(dto.assignedToId !== undefined && { assignedToId: dto.assignedToId }),
        ...(dto.totalFindings !== undefined && { totalFindings: dto.totalFindings }),
        ...(dto.openFindings !== undefined && { openFindings: dto.openFindings }),
        ...(dto.critFindings !== undefined && { critFindings: dto.critFindings }),
        ...(dto.highFindings !== undefined && { highFindings: dto.highFindings }),
        ...(dto.slaCompliance !== undefined && { slaCompliance: dto.slaCompliance }),
        ...(dto.assessmentMeta !== undefined && { assessmentMeta: dto.assessmentMeta as never }),
      },
      select: REQUEST_SELECT,
    });

    const action = dto.assignedToId && dto.assignedToId !== existing.assignedToId
      ? AuditAction.ASSIGNED
      : AuditAction.UPDATED;

    await this.logAudit(actor.id, actor.name, action, id, existing, updated);
    return updated;
  }

  async updateStatus(
    id: string,
    dto: UpdateRequestStatusDto,
    actor: { id: string; name: string; role: UserRole },
  ) {
    const existing = await this.findOrFail(id);

    // RBAC: APPLICATION_OWNER and INFRASTRUCTURE_OWNER cannot change status
    const restrictedRoles: UserRole[] = [
      UserRole.APPLICATION_OWNER,
      UserRole.INFRASTRUCTURE_OWNER,
      UserRole.READ_ONLY,
    ];

    if (restrictedRoles.includes(actor.role)) {
      throw new ForbiddenException(
        'You do not have permission to change request status.',
      );
    }

    this.workflow.validate(existing.status, dto.status);

    const timestamps: Record<string, Date> = {};
    if (dto.status === 'SUBMITTED') timestamps.submittedAt = new Date();
    if (dto.status === 'IN_PROGRESS') timestamps.startedAt = new Date();
    if (dto.status === 'CLOSED') timestamps.closedAt = new Date();

    const updated = await this.prisma.securityRequest.update({
      where: { id },
      data: { status: dto.status, ...timestamps },
      select: REQUEST_SELECT,
    });

    await this.logAudit(
      actor.id, actor.name, AuditAction.STATUS_CHANGED, id,
      { status: existing.status },
      { status: dto.status, remarks: dto.remarks },
    );

    return updated;
  }

  async remove(id: string, actor: { id: string; name: string }) {
    await this.findOrFail(id);
    await this.prisma.securityRequest.update({
      where: { id },
      data: { deletedAt: new Date() },
    });
    await this.logAudit(actor.id, actor.name, AuditAction.DELETED, id);
    return { message: 'Security request deleted.' };
  }

  // ── Comments ────────────────────────────────────────────────────────────────

  async getComments(requestId: string) {
    await this.findOrFail(requestId);
    return this.prisma.comment.findMany({
      where: { requestId },
      orderBy: { createdAt: 'asc' },
      select: {
        id: true, body: true, authorName: true, authorRole: true,
        createdAt: true, updatedAt: true,
        author: { select: { id: true, name: true, email: true } },
      },
    });
  }

  async addComment(
    requestId: string,
    dto: AddCommentDto,
    actor: { id: string; name: string; role: string },
  ) {
    await this.findOrFail(requestId);

    const comment = await this.prisma.comment.create({
      data: {
        requestId,
        authorId: actor.id,
        authorName: actor.name,
        authorRole: actor.role,
        body: dto.body,
      },
      select: {
        id: true, body: true, authorName: true, authorRole: true, createdAt: true,
      },
    });

    await this.logAudit(actor.id, actor.name, AuditAction.COMMENTED, requestId, null, { commentId: comment.id });
    return comment;
  }

  // ── Attachments ─────────────────────────────────────────────────────────────

  async getAttachments(requestId: string) {
    await this.findOrFail(requestId);
    return this.prisma.attachment.findMany({
      where: { requestId },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true, filename: true, mimeType: true, sizeBytes: true,
        url: true, uploadedByName: true, createdAt: true,
      },
    });
  }

  async uploadAttachment(
    requestId: string,
    file: Express.Multer.File,
    actor: { id: string; name: string },
  ) {
    await this.findOrFail(requestId);

    if (file.size > MAX_SIZE_BYTES) {
      throw new BadRequestException('File exceeds the 20 MB size limit.');
    }
    if (!ALLOWED_MIME.includes(file.mimetype)) {
      throw new BadRequestException(`File type '${file.mimetype}' is not permitted.`);
    }

    // Persist to local uploads directory (MVP)
    if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
    const storageKey = `${requestId}/${Date.now()}-${file.originalname}`;
    const destPath = path.join(UPLOAD_DIR, storageKey.replace('/', path.sep));
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    fs.writeFileSync(destPath, file.buffer);

    const attachment = await this.prisma.attachment.create({
      data: {
        requestId,
        uploadedById: actor.id,
        uploadedByName: actor.name,
        filename: file.originalname,
        mimeType: file.mimetype,
        sizeBytes: file.size,
        storageKey,
        url: `/uploads/security-requests/${storageKey}`,
      },
      select: {
        id: true, filename: true, mimeType: true, sizeBytes: true, url: true, createdAt: true,
      },
    });

    await this.logAudit(actor.id, actor.name, AuditAction.ATTACHED, requestId, null, { attachmentId: attachment.id, filename: file.originalname });
    return attachment;
  }
}
