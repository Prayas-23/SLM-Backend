import { Processor, WorkerHost, InjectQueue } from '@nestjs/bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { Job, Queue } from 'bullmq';
import { PrismaService } from '../../prisma/prisma.service';
import { ReportGenerationService } from '../report-generation.service';
import { ReportStatus, AuditAction, AuditEntityType } from '@prisma/client';
import { ReportType, ReportFormat } from '../dto/report.dto';
import * as path from 'path';
import * as fs from 'fs';
import { REPORTS_DIR } from '../report-generation.service';

// ── Queue & Job name constants ─────────────────────────────────────────────────
export const REPORT_QUEUE = 'report-generation';
export const REPORT_GENERATE_JOB = 'report:generate';
export const REPORT_SCHEDULER_TICK_JOB = 'report:scheduler-tick';
export const REPORT_EXPIRE_STALE_JOB = 'report:expire-stale';

export interface ReportJobPayload {
  reportId: string;
  type: ReportType;
  format: ReportFormat;
  actorId?: string;
  actorName?: string;
  environment?: string;
  startDate?: string;
  endDate?: string;
  severity?: any;
  status?: string;
  source?: string;
  assignmentMethod?: any;
  owner?: string;
  asset?: string;
  application?: string;
  myPending?: string;
}

// ── BullMQ Processor ───────────────────────────────────────────────────────────

@Processor(REPORT_QUEUE)
export class ReportGenerationJob extends WorkerHost {
  private readonly logger = new Logger(ReportGenerationJob.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly generator: ReportGenerationService,
  ) {
    super();
  }

  async process(job: Job): Promise<void> {
    // ── Recurring: scheduler tick ──────────────────────────────────────────────
    // scheduler temporarily disabled 
    //   if(job.name === REPORT_SCHEDULER_TICK_JOB) {
    //   this.logger.debug('Scheduler tick executing...');
    //   await this.scheduler.processDueSchedules();
    //   return;
    // }

    // ── Recurring: expire stale reports ───────────────────────────────────────
    if (job.name === REPORT_EXPIRE_STALE_JOB) {
      this.logger.debug('Running report expiry cleanup...');
      await this.expireStaleReports();
      return;
    }

    // ── Default: generate report ───────────────────────────────────────────────
    const { 
      reportId, type, format, actorId, actorName, environment, 
      startDate, endDate, severity, status, source, assignmentMethod, 
      owner, asset, application, myPending
    } = job.data as ReportJobPayload;

    this.logger.log(`[${job.name}] Processing report ${reportId} (${type}/${format})`);

    // Mark as GENERATING
    await this.prisma.report.update({
      where: { id: reportId },
      data: { status: ReportStatus.GENERATING },
    });

    try {
      const { storageKey, url } = await this.generator.generate({
        reportId,
        type,
        format,
        environment: environment as never,
        startDate,
        endDate,
        severity,
        status,
        source,
        assignmentMethod,
        owner,
        asset,
        application,
        myPending,
        actorId,
      });

      const expiresAt = new Date();
      expiresAt.setHours(expiresAt.getHours() + 72);

      await this.prisma.report.update({
        where: { id: reportId },
        data: {
          status: ReportStatus.READY,
          storageKey,
          url,
          generatedAt: new Date(),
          expiresAt,
        },
      });

      await this.prisma.auditLog.create({
        data: {
          actorId: actorId ?? null,
          actorName: actorName ?? 'System',
          entityType: AuditEntityType.REPORT,
          entityId: reportId,
          action: AuditAction.CREATED,
          after: { status: ReportStatus.READY, url, format, type } as never,
        },
      });

      this.logger.log(`[${job.name}] Report ${reportId} READY — ${url}`);
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      this.logger.error(`[${job.name}] Report ${reportId} FAILED — ${errorMsg}`);

      await this.prisma.report.update({
        where: { id: reportId },
        data: { status: ReportStatus.FAILED },
      });

      await this.prisma.auditLog.create({
        data: {
          actorId: actorId ?? null,
          actorName: actorName ?? 'System',
          entityType: AuditEntityType.REPORT,
          entityId: reportId,
          action: AuditAction.UPDATED,
          after: { status: ReportStatus.FAILED, error: errorMsg } as never,
        },
      });

      throw err; // Let BullMQ retry per queue config
    }
  }

  // ── Internal: expire stale reports ─────────────────────────────────────────

  private async expireStaleReports(): Promise<void> {
    const now = new Date();
    const stale = await this.prisma.report.findMany({
      where: { status: ReportStatus.READY, expiresAt: { lte: now } },
      select: { id: true, storageKey: true },
    });

    for (const r of stale) {
      if (r.storageKey) {
        const filePath = path.join(REPORTS_DIR, path.basename(r.storageKey));
        if (fs.existsSync(filePath)) {
          try { fs.unlinkSync(filePath); } catch { /* ignore */ }
        }
      }
      await this.prisma.report.update({
        where: { id: r.id },
        data: { status: ReportStatus.EXPIRED },
      });
    }

    if (stale.length > 0) {
      this.logger.log(`Expired ${stale.length} stale report(s).`);
    }
  }
}

// ── Queue Producer helper (injectable) ────────────────────────────────────────

@Injectable()
export class ReportQueueProducer {
  private readonly logger = new Logger(ReportQueueProducer.name);

  constructor(
    @InjectQueue(REPORT_QUEUE) private readonly queue: Queue<ReportJobPayload>,
  ) { }

  async enqueue(payload: ReportJobPayload): Promise<string | undefined> {
    const job = await this.queue.add(REPORT_GENERATE_JOB, payload, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 5000 },
      removeOnComplete: 100,
      removeOnFail: 50,
    });
    this.logger.log(`Enqueued report job #${job.id} for report ${payload.reportId}`);
    return job.id;
  }
}
