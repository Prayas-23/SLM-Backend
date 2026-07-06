import { Injectable, Logger } from '@nestjs/common';

export interface SlaNotificationPayload {
  vulnerabilityId: string;
  vulnId: string;
  shortDesc: string;
  severity: string;
  slaDueDate: Date;
  daysRemaining: number;
  assignedToEmail?: string;
  securityLeadEmail?: string;
}

/**
 * SLA Notification Service — stub implementation.
 * Logs all triggers to console. Replace with nodemailer / SES in production.
 */
@Injectable()
export class SlaNotificationService {
  private readonly logger = new Logger(SlaNotificationService.name);

  /** Fired when 7 days remain before SLA breach */
  async notifySevenDayWarning(payload: SlaNotificationPayload): Promise<void> {
    this.logger.warn(
      `[SLA 7-DAY] ${payload.vulnId} | ${payload.severity} | ` +
      `Due: ${payload.slaDueDate.toISOString()} | Assigned: ${payload.assignedToEmail ?? 'unassigned'}`,
    );
    // TODO: send email via nodemailer / AWS SES
  }

  /** Fired when 3 days remain before SLA breach */
  async notifyThreeDayWarning(payload: SlaNotificationPayload): Promise<void> {
    this.logger.warn(
      `[SLA 3-DAY] ${payload.vulnId} | ${payload.severity} | ` +
      `Due: ${payload.slaDueDate.toISOString()} | Assigned: ${payload.assignedToEmail ?? 'unassigned'}`,
    );
    // TODO: send email via nodemailer / AWS SES
  }

  /** Fired when 1 day remains before SLA breach */
  async notifyOneDayWarning(payload: SlaNotificationPayload): Promise<void> {
    this.logger.error(
      `[SLA 1-DAY] ${payload.vulnId} | ${payload.severity} | ` +
      `Due: ${payload.slaDueDate.toISOString()} | Assigned: ${payload.assignedToEmail ?? 'unassigned'}`,
    );
    // TODO: send urgent email / Slack alert
  }

  /** Fired when SLA is breached (daysRemaining < 0) */
  async notifyBreached(payload: SlaNotificationPayload): Promise<void> {
    this.logger.error(
      `[SLA BREACHED] ${payload.vulnId} | ${payload.severity} | ` +
      `Breached on: ${payload.slaDueDate.toISOString()} | ` +
      `Assigned: ${payload.assignedToEmail ?? 'unassigned'}`,
    );
    // TODO: send breach alert email + escalate to security lead
  }
}
