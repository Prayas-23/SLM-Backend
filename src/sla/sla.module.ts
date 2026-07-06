import { Module, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { SlaController } from './sla.controller';
import { SlaMetricsService } from './sla-metrics.service';
import { SlaNotificationService } from './sla-notification.service';
import { SlaRefreshJob, SLA_QUEUE, SLA_REFRESH_JOB } from './jobs/sla-refresh.job';

@Module({
  imports: [
    BullModule.registerQueue({ name: SLA_QUEUE }),
  ],
  controllers: [SlaController],
  providers: [SlaMetricsService, SlaNotificationService, SlaRefreshJob],
  exports: [SlaMetricsService],
})
export class SlaModule implements OnModuleInit {
  constructor(@InjectQueue(SLA_QUEUE) private readonly slaQueue: Queue) {}

  /**
   * Schedule the recurring SLA refresh job on module init.
   * Runs every hour. BullMQ de-duplicates by jobId so restarts are safe.
   */
  async onModuleInit(): Promise<void> {
    await this.slaQueue.add(
      SLA_REFRESH_JOB,
      {},
      {
        repeat: { every: 60 * 60 * 1000 }, // 1 hour in ms
        jobId: 'sla-refresh-recurring',
        removeOnComplete: 50,
        removeOnFail: 20,
      },
    );
  }
}
