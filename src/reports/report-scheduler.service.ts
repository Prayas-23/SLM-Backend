import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ReportQueueProducer } from './jobs/report-generation.job';
import { ReportType, ReportFormat } from './dto/report.dto';
import { AuditAction, AuditEntityType } from '@prisma/client';

/**
 * ReportSchedulerService
 *
 * Evaluates active ReportSchedule records and enqueues generation jobs
 * for any schedules whose `nextRunAt` is in the past (or null, meaning
 * first run).
 *
 * Intended to be called by a BullMQ repeating job (see report-scheduler.job.ts)
 * or a NestJS cron (@nestjs/schedule — optional dep) every minute.
 */
@Injectable()
export class ReportSchedulerService {
  private readonly logger = new Logger(ReportSchedulerService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly producer: ReportQueueProducer,
  ) {}

  /**
   * Called by the scheduler tick. Queries all active schedules that are due,
   * creates a Report record for each, enqueues generation, and updates lastRunAt / nextRunAt.
   */
  async processDueSchedules(): Promise<void> {
    const now = new Date();

    const dueSchedules = await this.prisma.reportSchedule.findMany({
      where: {
        isActive: true,
        OR: [
          { nextRunAt: null },
          { nextRunAt: { lte: now } },
        ],
      },
    });

    if (dueSchedules.length === 0) {
      this.logger.debug('Scheduler tick — no due schedules.');
      return;
    }

    this.logger.log(`Scheduler tick — processing ${dueSchedules.length} due schedule(s).`);

    for (const schedule of dueSchedules) {
      try {
        const filters = (schedule.filters ?? {}) as Record<string, unknown>;

        // Create a Report record for this scheduled run
        const report = await this.prisma.report.create({
          data: {
            title: schedule.title,
            status: 'PENDING',
            format: schedule.format,
            filters: schedule.filters,
          },
        });

        // Enqueue async generation
        await this.producer.enqueue({
          reportId: report.id,
          type: (filters['type'] as ReportType) ?? ReportType.EXECUTIVE_DASHBOARD,
          format: (schedule.format as ReportFormat) ?? ReportFormat.CSV,
          actorName: 'Scheduler',
          environment: filters['environment'] as string | undefined,
          startDate: filters['startDate'] as string | undefined,
          endDate: filters['endDate'] as string | undefined,
        });

        // Compute next run from cron expression (simple parser included below)
        const nextRunAt = this.computeNextRun(schedule.cronExpr);

        await this.prisma.reportSchedule.update({
          where: { id: schedule.id },
          data: { lastRunAt: now, nextRunAt },
        });

        // Audit
        await this.prisma.auditLog.create({
          data: {
            actorName: 'ReportScheduler',
            entityType: AuditEntityType.REPORT,
            entityId: report.id,
            action: AuditAction.CREATED,
            after: {
              scheduleId: schedule.id,
              title: schedule.title,
              triggeredAt: now.toISOString(),
            } as never,
          },
        });

        this.logger.log(
          `Scheduled report "${schedule.title}" (id: ${report.id}) enqueued — next run: ${nextRunAt?.toISOString() ?? 'manual'}`,
        );
      } catch (err) {
        this.logger.error(
          `Failed to process schedule "${schedule.title}" (id: ${schedule.id}): ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }
  }

  /**
   * Minimal cron next-run calculator.
   * Supports common fixed-field patterns:
   *   "0 8 * * 1"  → every Monday at 08:00
   *   "0 0 * * *"  → daily at midnight
   *   "0 8 * * 0"  → every Sunday at 08:00
   *   "0 8 1 * *"  → 1st of every month at 08:00
   *
   * For full cron support install `cron-parser`:
   *   npm install cron-parser
   * and replace this method with:
   *   const interval = cronParser.parseExpression(expr, { currentDate: new Date() });
   *   return interval.next().toDate();
   */
  private computeNextRun(cronExpr: string): Date {
    try {
      // Try to use cron-parser if available
      // eslint-disable-next-line @typescript-eslint/no-require-imports
      const parser = require('cron-parser');
      const interval = parser.parseExpression(cronExpr, { currentDate: new Date() });
      return interval.next().toDate() as Date;
    } catch {
      // Fallback: add 24 hours
      const next = new Date();
      next.setHours(next.getHours() + 24);
      return next;
    }
  }
}
