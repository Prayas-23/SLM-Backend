import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { PrismaService } from '../../prisma/prisma.service';
import { SlaNotificationService } from '../sla-notification.service';
import { VulnerabilityStatus } from '@prisma/client';

export const SLA_QUEUE = 'sla-refresh';
export const SLA_REFRESH_JOB = 'sla:refresh';

const ACTIVE_STATUSES: VulnerabilityStatus[] = [
  VulnerabilityStatus.OPEN,
  VulnerabilityStatus.ASSIGNED,
  VulnerabilityStatus.IN_PROGRESS,
  VulnerabilityStatus.PATCHED,
  VulnerabilityStatus.PENDING_REVALIDATION,
];

@Processor(SLA_QUEUE)
export class SlaRefreshJob extends WorkerHost {
  private readonly logger = new Logger(SlaRefreshJob.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly notify: SlaNotificationService,
  ) {
    super();
  }

  async process(job: Job): Promise<void> {
    this.logger.log(`[${job.name}] SLA refresh started — job #${job.id}`);
    const now = new Date();

    // Fetch all active SLA tracking records with vuln details
    const records = await this.prisma.slaTracking.findMany({
      where: {
        vulnerability: {
          deletedAt: null,
          status: { in: ACTIVE_STATUSES },
        },
      },
      include: {
        vulnerability: {
          select: {
            id: true, vulnId: true, shortDesc: true,
            severity: true, slaDueDate: true,
            assignedTo: { select: { email: true } },
          },
        },
      },
    });

    this.logger.log(`[${job.name}] Processing ${records.length} SLA records...`);

    let breachCount = 0;
    let updatedCount = 0;

    for (const record of records) {
      const vuln = record.vulnerability;
      if (!vuln.slaDueDate) continue;

      const dueDate = new Date(vuln.slaDueDate);
      const msRemaining = dueDate.getTime() - now.getTime();
      const daysRemaining = Math.ceil(msRemaining / (1000 * 60 * 60 * 24));
      const isBreached = msRemaining < 0;

      const updateData: Record<string, unknown> = { daysRemaining };

      if (isBreached && !record.isBreached) {
        updateData.isBreached = true;
        updateData.breachedAt = now;
        breachCount++;

        await this.notify.notifyBreached({
          vulnerabilityId: vuln.id,
          vulnId: vuln.vulnId,
          shortDesc: vuln.shortDesc,
          severity: vuln.severity,
          slaDueDate: dueDate,
          daysRemaining,
          assignedToEmail: vuln.assignedTo?.email,
        });
      }

      // Notification hooks — fire when threshold crossed
      if (!isBreached) {
        const payload = {
          vulnerabilityId: vuln.id,
          vulnId: vuln.vulnId,
          shortDesc: vuln.shortDesc,
          severity: vuln.severity,
          slaDueDate: dueDate,
          daysRemaining,
          assignedToEmail: vuln.assignedTo?.email,
        };

        // Only fire on exact-day crossing (within current run window)
        if (daysRemaining === 7) await this.notify.notifySevenDayWarning(payload);
        if (daysRemaining === 3) await this.notify.notifyThreeDayWarning(payload);
        if (daysRemaining === 1) await this.notify.notifyOneDayWarning(payload);
      }

      await this.prisma.slaTracking.update({
        where: { id: record.id },
        data: updateData,
      });

      updatedCount++;
    }

    this.logger.log(
      `[${job.name}] Done — updated: ${updatedCount}, newly breached: ${breachCount}`,
    );
  }
}
