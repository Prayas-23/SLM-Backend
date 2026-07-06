import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { ConfigService } from '@nestjs/config';
import { IEmailProvider } from './providers/email.provider.interface';
import { NotificationProviderFactory } from './providers/notification-provider.factory';
import { EmailTemplates, VulnTemplateContext } from './templates/email.templates';
import {
  SettingCategory,
  AuditAction,
  AuditEntityType,
  Vulnerability,
  Application,
  InfrastructureAsset,
  User,
} from '@prisma/client';

// ── Relation shape expected from VulnerabilitiesService queries ───────────────
type VulnWithRelations = Vulnerability & {
  request?: {
    targetApp?: (Application & { owner?: Pick<User, 'email'> | null }) | null;
    targetInfra?: (InfrastructureAsset & { assetOwner?: Pick<User, 'email'> | null }) | null;
  } | null;
  assignedTo?: Pick<User, 'id' | 'name' | 'email'> | null;
};

@Injectable()
export class NotificationsService implements OnModuleInit {
  private readonly logger = new Logger(NotificationsService.name);

  /**
   * Active provider — replaced on every refreshConfig() call.
   * Always resolved through NotificationProviderFactory, never instantiated directly.
   */
  private emailProvider: IEmailProvider | null = null;

  /** Flat map of all notifications.* PlatformSettings keys → values */
  private settingsCache: Record<string, string> = {};

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly providerFactory: NotificationProviderFactory,
  ) {}

  async onModuleInit() {
    await this.refreshConfig();
  }

  // ── Configuration ───────────────────────────────────────────────────────────

  /**
   * Loads NOTIFICATIONS settings from PlatformSetting and rebuilds the
   * active provider via NotificationProviderFactory.
   *
   * Called at startup (onModuleInit) and after every successful settings
   * update (dynamic refresh — no server restart required).
   */
  async refreshConfig(): Promise<void> {
    const settings = await this.prisma.platformSetting.findMany({
      where: { category: SettingCategory.NOTIFICATIONS },
    });

    this.settingsCache = {};
    for (const s of settings) {
      this.settingsCache[s.key] = s.value;
    }

    const providerType = this.settingsCache['notifications.provider'] || 'RESEND';

    this.emailProvider = this.providerFactory.create(providerType, {
      apiKey: this.settingsCache['notifications.resend.apiKey'] || '',
      senderEmail: this.settingsCache['notifications.sender.email'] || '',
      senderName: this.settingsCache['notifications.sender.name'] || '',
    });

    this.logger.log(
      `Notification config refreshed — provider: ${providerType}, enabled: ${this.isEnabled()}`,
    );
  }

  private isEnabled(): boolean {
    return this.settingsCache['notifications.enabled'] === 'true';
  }

  private buildLink(path: string): string {
    const baseUrl = this.config.get<string>('FRONTEND_URL') || 'http://localhost:5173';
    return `${baseUrl}${path}`;
  }

  private buildContext(vuln: VulnWithRelations): VulnTemplateContext {
    return {
      vulnId: vuln.vulnId,
      title: vuln.shortDesc || vuln.type,
      severity: vuln.severity,
      status: vuln.status,
      appName: vuln.request?.targetApp?.name,
      assetName: vuln.request?.targetInfra?.serverName,
      assignedOwner: vuln.assignedTo?.name,
      link: this.buildLink(`/vuln/vuln/${vuln.id}`),
    };
  }

  // ── Internal dispatch ───────────────────────────────────────────────────────

  private async dispatchEmail(
    event: string,
    recipientEmail: string,
    subject: string,
    html: string,
  ): Promise<void> {
    if (!this.isEnabled() || !this.emailProvider || !recipientEmail) return;

    try {
      await this.emailProvider.sendEmail({ to: recipientEmail, subject, html });
      await this.logAudit(event, recipientEmail, 'SUCCESS');
    } catch (error) {
      this.logger.error(
        `Notification failed — event: ${event}, recipient: ${recipientEmail}`,
        error,
      );
      await this.logAudit(event, recipientEmail, 'FAILED', String(error));
      // ⚠️  Do NOT re-throw. Notification failures must never interrupt
      // the calling business transaction (vulnerability create/update/status).
    }
  }

  private async logAudit(
    event: string,
    recipient: string,
    status: 'SUCCESS' | 'FAILED',
    errorMsg?: string,
  ): Promise<void> {
    await this.prisma.auditLog
      .create({
        data: {
          // REPORT is the closest generic AuditEntityType available in the MVP schema.
          entityType: AuditEntityType.REPORT,
          entityId: 'NOTIFICATION',
          action: AuditAction.CREATED,
          metadata: {
            event,
            recipient,
            provider: this.settingsCache['notifications.provider'] || 'RESEND',
            status,
            ...(errorMsg && { error: errorMsg }),
          },
        },
      })
      .catch((err) => this.logger.error('Failed to write notification audit log', err));
  }

  // ── Public Business Methods ─────────────────────────────────────────────────
  // These methods form the public API of the Notification Framework.
  // Business modules (VulnerabilitiesService, etc.) call these and are
  // completely unaware of which provider handles delivery.

  async sendVulnerabilityCreated(vuln: VulnWithRelations): Promise<void> {
    const appOwnerEmail =
      vuln.request?.targetApp?.owner?.email ||
      vuln.request?.targetInfra?.assetOwner?.email;
    if (!appOwnerEmail) return;

    const html = EmailTemplates.vulnerabilityCreated(this.buildContext(vuln));
    await this.dispatchEmail(
      'VULNERABILITY_CREATED',
      appOwnerEmail,
      `New Vulnerability Reported: ${vuln.vulnId}`,
      html,
    );
  }

  async sendAssignment(vuln: VulnWithRelations): Promise<void> {
    const assigneeEmail = vuln.assignedTo?.email;
    if (!assigneeEmail) return;

    const html = EmailTemplates.vulnerabilityAssigned(this.buildContext(vuln));
    await this.dispatchEmail(
      'VULNERABILITY_ASSIGNED',
      assigneeEmail,
      `Assigned to You: ${vuln.vulnId}`,
      html,
    );
  }

  async sendRevalidationSubmitted(
    vuln: VulnWithRelations,
    securityTeamEmail: string,
  ): Promise<void> {
    if (!securityTeamEmail) return;

    const html = EmailTemplates.revalidationSubmitted(this.buildContext(vuln));
    await this.dispatchEmail(
      'REVALIDATION_SUBMITTED',
      securityTeamEmail,
      `Ready for Revalidation: ${vuln.vulnId}`,
      html,
    );
  }

  async sendRevalidationFailed(vuln: VulnWithRelations): Promise<void> {
    const appOwnerEmail =
      vuln.request?.targetApp?.owner?.email ||
      vuln.request?.targetInfra?.assetOwner?.email;
    const assigneeEmail = vuln.assignedTo?.email;

    const recipients = [...new Set([appOwnerEmail, assigneeEmail].filter(Boolean))] as string[];
    if (recipients.length === 0) return;

    const html = EmailTemplates.revalidationFailed(this.buildContext(vuln));
    // Dispatch individually — each gets its own audit trail entry
    for (const email of recipients) {
      await this.dispatchEmail(
        'REVALIDATION_FAILED',
        email,
        `Revalidation Failed: ${vuln.vulnId}`,
        html,
      );
    }
  }

  async sendVulnerabilityClosed(vuln: VulnWithRelations): Promise<void> {
    const appOwnerEmail =
      vuln.request?.targetApp?.owner?.email ||
      vuln.request?.targetInfra?.assetOwner?.email;
    if (!appOwnerEmail) return;

    const html = EmailTemplates.vulnerabilityClosed(this.buildContext(vuln));
    await this.dispatchEmail(
      'VULNERABILITY_CLOSED',
      appOwnerEmail,
      `Vulnerability Closed: ${vuln.vulnId}`,
      html,
    );
  }

  /** POST /notifications/test — called by the Settings UI to verify credentials. */
  async sendTestEmail(recipient: string): Promise<void> {
    // Force an immediate config refresh before the test so the UI's
    // just-saved API key is picked up without a restart.
    await this.refreshConfig();

    const html = `
      <h2>Test Notification</h2>
      <p>This is a test email from Sentinel SLM to verify your notification settings are configured correctly.</p>
    `;
    await this.dispatchEmail(
      'TEST_CONNECTION',
      recipient,
      'Sentinel SLM: Test Notification',
      html,
    );
  }
}
