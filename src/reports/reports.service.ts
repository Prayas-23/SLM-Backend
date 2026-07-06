import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ReportQueueProducer } from './jobs/report-generation.job';
import {
  GenerateReportDto,
  ScheduleReportDto,
  UpdateScheduleDto,
  ListReportsDto,
  ReportResponse,
  ScheduleResponse,
} from './dto/report.dto';
import {
  AuditAction,
  AuditEntityType,
  ReportStatus,
} from '@prisma/client';
import * as path from 'path';
import * as fs from 'fs';

// ── Shared select shape ────────────────────────────────────────────────────────
const REPORT_SELECT = {
  id: true, title: true, status: true, format: true,
  filters: true, url: true, expiresAt: true, generatedAt: true, createdAt: true,
  requestedBy: { select: { id: true, name: true, email: true } },
} as const;

const SCHEDULE_SELECT = {
  id: true, title: true, cronExpr: true, format: true,
  filters: true, recipients: true, isActive: true,
  lastRunAt: true, nextRunAt: true, createdAt: true,
} as const;

@Injectable()
export class ReportsService {
  private readonly logger = new Logger(ReportsService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly producer: ReportQueueProducer,
  ) { }

  // ── List reports ────────────────────────────────────────────────────────────

  async findAll(filter: ListReportsDto, actorId: string): Promise<ReportResponse[]> {
    const where: Record<string, unknown> = {
      requestedById: actorId,
    };
    if (filter.status) where.status = filter.status;
    if (filter.startDate || filter.endDate) {
      where.createdAt = {
        ...(filter.startDate && { gte: new Date(filter.startDate) }),
        ...(filter.endDate && { lte: new Date(filter.endDate) }),
      };
    }

    return this.prisma.report.findMany({
      where,
      select: REPORT_SELECT,
      orderBy: { createdAt: 'desc' },
    }) as Promise<ReportResponse[]>;
  }

  // ── Get single report ───────────────────────────────────────────────────────

  async findOne(id: string): Promise<ReportResponse> {
    const report = await this.prisma.report.findUnique({
      where: { id },
      select: REPORT_SELECT,
    });
    if (!report) throw new NotFoundException(`Report '${id}' not found.`);
    return report as ReportResponse;
  }

  // ── Generate report (async via BullMQ) ─────────────────────────────────────

  async generate(
    dto: GenerateReportDto,
    actor: { id: string; name: string },
  ): Promise<ReportResponse> {
    const filters = {
      type: dto.type,
      format: dto.format,
      environment: dto.environment,
      startDate: dto.startDate,
      endDate: dto.endDate,
      severity: dto.severity,
      status: dto.status,
      source: dto.source,
      assignmentMethod: dto.assignmentMethod,
      owner: dto.owner,
      asset: dto.asset,
      application: dto.application,
      myPending: (dto as unknown as { myPending?: string }).myPending, // since we didn't add it to all DTOs strictly
    };

    const report = await this.prisma.report.create({
      data: {
        title: dto.title,
        status: ReportStatus.PENDING,
        format: dto.format,
        filters,
        requestedById: actor.id,
      },
      select: REPORT_SELECT,
    });

    // Enqueue async generation
    await this.producer.enqueue({
      reportId: report.id,
      type: dto.type,
      format: dto.format,
      actorId: actor.id,
      actorName: actor.name,
      environment: dto.environment,
      startDate: dto.startDate,
      endDate: dto.endDate,
      severity: dto.severity,
      status: dto.status,
      source: dto.source,
      assignmentMethod: dto.assignmentMethod,
      owner: dto.owner,
      asset: dto.asset,
      application: dto.application,
      myPending: (dto as unknown as { myPending?: string }).myPending,
    });

    // Audit
    await this.prisma.auditLog.create({
      data: {
        actorId: actor.id,
        actorName: actor.name,
        entityType: AuditEntityType.REPORT,
        entityId: report.id,
        action: AuditAction.CREATED,
        after: { title: dto.title, type: dto.type, format: dto.format } as never,
      },
    });

    this.logger.log(`Report "${dto.title}" (id: ${report.id}) queued by ${actor.name}`);
    return report as ReportResponse;
  }

  // ── Download report file ────────────────────────────────────────────────────

  async getDownloadStream(
    id: string,
  ): Promise<{ stream: fs.ReadStream; filename: string; mime: string }> {
    const report = await this.prisma.report.findUnique({
      where: { id },
      select: { status: true, storageKey: true, format: true, title: true, expiresAt: true },
    });

    if (!report) throw new NotFoundException(`Report '${id}' not found.`);
    if (report.status !== ReportStatus.READY) {
      throw new BadRequestException(
        `Report is not ready for download — current status: ${report.status}`,
      );
    }
    if (report.expiresAt && new Date() > report.expiresAt) {
      throw new BadRequestException('Report has expired. Please generate a new report.');
    }
    if (!report.storageKey) {
      throw new BadRequestException('Report file is not available.');
    }

    const filePath = path.join(process.cwd(), 'uploads', report.storageKey);
    if (!fs.existsSync(filePath)) {
      throw new NotFoundException('Report file not found on disk. It may have been cleaned up.');
    }

    const isXlsx = report.format?.toUpperCase() === 'XLSX';
    const ext = isXlsx ? 'xlsx' : 'csv';
    const mime = isXlsx
      ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
      : 'text/csv';

    const safeTitle = report.title.replace(/[^a-z0-9_\-]/gi, '_').toLowerCase();
    const filename = `${safeTitle}.${ext}`;

    return { stream: fs.createReadStream(filePath), filename, mime };
  }

  // ── Schedule management ─────────────────────────────────────────────────────

  async createSchedule(
    dto: ScheduleReportDto,
    actor: { id: string; name: string },
  ): Promise<ScheduleResponse> {
    const filters = {
      type: dto.type,
      format: dto.format,
      environment: dto.environment,
      startDate: dto.startDate,
      endDate: dto.endDate,
      severity: dto.severity,
      status: dto.status,
      source: dto.source,
      assignmentMethod: dto.assignmentMethod,
      owner: dto.owner,
      asset: dto.asset,
      application: dto.application,
    };

    // Validate cron expression length (basic guard)
    const parts = dto.cronExpr.trim().split(/\s+/);
    if (parts.length < 5 || parts.length > 6) {
      throw new BadRequestException(
        'Invalid cron expression. Expected 5 or 6 space-separated fields.',
      );
    }

    const schedule = await this.prisma.reportSchedule.create({
      data: {
        title: dto.title,
        cronExpr: dto.cronExpr,
        format: dto.format,
        filters,
        recipients: dto.recipients,
      },
      select: SCHEDULE_SELECT,
    });

    await this.prisma.auditLog.create({
      data: {
        actorId: actor.id,
        actorName: actor.name,
        entityType: AuditEntityType.REPORT,
        entityId: schedule.id,
        action: AuditAction.CREATED,
        after: { title: dto.title, cronExpr: dto.cronExpr, recipients: dto.recipients } as never,
      },
    });

    this.logger.log(`Schedule "${dto.title}" (id: ${schedule.id}) created by ${actor.name}`);
    return schedule as ScheduleResponse;
  }

  async updateSchedule(
    id: string,
    dto: UpdateScheduleDto,
    actor: { id: string; name: string },
  ): Promise<ScheduleResponse> {
    const existing = await this.prisma.reportSchedule.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException(`ReportSchedule '${id}' not found.`);

    if (dto.cronExpr) {
      const parts = dto.cronExpr.trim().split(/\s+/);
      if (parts.length < 5 || parts.length > 6) {
        throw new BadRequestException('Invalid cron expression.');
      }
    }

    // Merge filters if any filter fields are updated
    const existingFilters = (existing.filters ?? {}) as Record<string, unknown>;
    const newFilters: Record<string, unknown> = { ...existingFilters };
    if (dto.environment !== undefined) newFilters['environment'] = dto.environment;
    if (dto.startDate !== undefined) newFilters['startDate'] = dto.startDate;
    if (dto.endDate !== undefined) newFilters['endDate'] = dto.endDate;
    if (dto.format !== undefined) newFilters['format'] = dto.format;

    const updated = await this.prisma.reportSchedule.update({
      where: { id },
      data: {
        ...(dto.title && { title: dto.title }),
        ...(dto.cronExpr && { cronExpr: dto.cronExpr }),
        ...(dto.format && { format: dto.format }),
        ...(dto.recipients && { recipients: dto.recipients }),
        ...(dto.isActive !== undefined && { isActive: dto.isActive }),
        filters: newFilters as import('@prisma/client').Prisma.InputJsonValue,
      },
      select: SCHEDULE_SELECT,
    });

    await this.prisma.auditLog.create({
      data: {
        actorId: actor.id,
        actorName: actor.name,
        entityType: AuditEntityType.REPORT,
        entityId: id,
        action: AuditAction.UPDATED,
        before: existing as never,
        after: updated as never,
      },
    });

    return updated as ScheduleResponse;
  }

  async deleteSchedule(id: string, actor: { id: string; name: string }): Promise<{ message: string }> {
    const existing = await this.prisma.reportSchedule.findUnique({ where: { id } });
    if (!existing) throw new NotFoundException(`ReportSchedule '${id}' not found.`);

    await this.prisma.reportSchedule.delete({ where: { id } });

    await this.prisma.auditLog.create({
      data: {
        actorId: actor.id,
        actorName: actor.name,
        entityType: AuditEntityType.REPORT,
        entityId: id,
        action: AuditAction.DELETED,
        before: existing as never,
      },
    });

    return { message: `ReportSchedule '${id}' deleted.` };
  }
}
