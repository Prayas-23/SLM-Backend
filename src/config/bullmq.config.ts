import { ConfigService } from '@nestjs/config';
import {
  BullRootModuleOptions,
  SharedBullConfigurationFactory,
} from '@nestjs/bullmq';
import { getRedisConfig } from './redis.config';

/**
 * Sentinel SLM — BullMQ Base Queue Configuration
 *
 * Provides a reusable factory for registering queues across modules.
 * Queue names follow the convention: sentinel_slm:<queue-name>
 *
 * Planned queues (to be registered in their respective modules):
 *   - notifications       → notify users on vuln assignment, SLA breach, etc.
 *   - sla-monitor         → periodic SLA breach detection jobs
 *   - report-generation   → async PDF/XLSX report generation
 *   - integrations        → CloudSEK, Qualys sync jobs
 *   - audit               → async audit log flushing
 *   - ai-search           → AI embedding / index update jobs
 */

export const QUEUE_NAMES = {
  NOTIFICATIONS: 'notifications',
  SLA_MONITOR: 'sla-monitor',
  REPORT_GENERATION: 'report-generation',
  INTEGRATIONS: 'integrations',
  AUDIT: 'audit',
  AI_SEARCH: 'ai-search',
} as const;

export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

/**
 * BullMQ shared configuration factory.
 * Use this as the `forRootAsync` factory across the app.
 */
export class BullConfigService implements SharedBullConfigurationFactory {
  constructor(private readonly configService: ConfigService) { }

  createSharedConfiguration(): BullRootModuleOptions {
    const prefix = this.configService.get<string>('bullmq.prefix', 'sentinel_slm');
    return {
      connection: getRedisConfig(this.configService),
      prefix,
      defaultJobOptions: {
        attempts: 3,
        backoff: {
          type: 'exponential',
          delay: 2000,
        },
        removeOnComplete: { count: 100 },
        removeOnFail: { count: 500 },
      },
    };
  }
}
