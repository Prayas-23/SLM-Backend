import { Module, OnModuleInit } from '@nestjs/common';
import { BullModule, InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { ReportsController } from './reports.controller';
import { ReportsService } from './reports.service';
import { ReportGenerationService } from './report-generation.service';
import { ReportSchedulerService } from './report-scheduler.service';
import {
  ReportGenerationJob,
  ReportQueueProducer,
  REPORT_QUEUE,
  REPORT_GENERATE_JOB,
} from './jobs/report-generation.job';

/**
 * Reports Module — Phase 2H
 *
 * Provides async report generation and scheduling for Sentinel SLM.
 *
 * Queue:  report-generation  (BullMQ / Redis)
 * Files:  uploads/reports/   (local disk, 72-hour expiry)
 *
 * Endpoints:
 *   GET    /reports                    — list own reports
 *   GET    /reports/:id                — get report details
 *   POST   /reports/generate           — enqueue async generation (202 ACCEPTED)
 *   POST   /reports/schedule           — create recurring schedule
 *   PATCH  /reports/schedule/:id       — update schedule
 *   DELETE /reports/schedule/:id       — delete schedule (SECURITY_LEAD only)
 *   GET    /reports/download/:id       — stream download
 *
 * Supported report types:
 *   VULNERABILITIES | SECURITY_REQUESTS | SLA | APPLICATIONS
 *   INFRASTRUCTURE_ASSETS | CLOUD_RESOURCES | EXECUTIVE_DASHBOARD
 *
 * Supported formats: CSV | XLSX (XLSX requires: npm install exceljs)
 */
@Module({
  imports: [
    BullModule.registerQueue({ name: REPORT_QUEUE }),
  ],
  controllers: [ReportsController],
  providers: [
    ReportsService,            // CRUD + download + schedule management
    ReportGenerationService,   // Fetches data + writes CSV/XLSX files
    ReportGenerationJob,       // BullMQ @Processor (generate + tick + expiry)
    ReportQueueProducer,       // Injectable queue producer
  ],
  exports: [ReportsService],
})
export class ReportsModule implements OnModuleInit {
  constructor(
    @InjectQueue(REPORT_QUEUE) private readonly reportQueue: Queue,
  ) { }

  /**
   * Schedule a recurring "scheduler tick" job on module init.
   * Runs every 5 minutes and evaluates due ReportSchedule records.
   * BullMQ de-duplicates by jobId so restarts are safe.
   */
  async onModuleInit(): Promise<void> {
    // await this.reportQueue.add(
    //   'report:scheduler-tick',
    //   {},
    //   {
    //     repeat: { every: 5 * 60 * 1000 }, // every 5 minutes
    //     jobId: 'report-scheduler-recurring',
    //     removeOnComplete: 20,
    //     removeOnFail: 10,
    //   },
    // );

    // Expire stale reports every 6 hours
    await this.reportQueue.add(
      'report:expire-stale',
      {},
      {
        repeat: { every: 6 * 60 * 60 * 1000 },
        jobId: 'report-expire-recurring',
        removeOnComplete: 10,
        removeOnFail: 5,
      },
    );
  }
}
