import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { BullModule } from '@nestjs/bullmq';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ApplicationsModule } from './applications/applications.module';
import { InfrastructureAssetsModule } from './infrastructure-assets/infrastructure-assets.module';
import { CloudAccountsModule } from './cloud-accounts/cloud-accounts.module';
import { CloudResourcesModule } from './cloud-resources/cloud-resources.module';
import { SecurityRequestsModule } from './security-requests/security-requests.module';
import { VulnerabilitiesModule } from './vulnerabilities/vulnerabilities.module';
import { SlaModule } from './sla/sla.module';
import { DashboardModule } from './dashboard/dashboard.module';
import { ReportsModule } from './reports/reports.module';
import { SettingsModule } from './settings/settings.module';
import { ScanFindingsModule } from './scan-findings/scan-findings.module';
import { ContinuousScanModule } from './continuous-scan/continuous-scan.module';
import { FindingsModule } from './findings/findings.module';
import { NotificationsModule } from './notifications/notifications.module';
import { AIModule } from './ai/ai.module';
import { ComplianceModule } from './compliance/compliance.module';
import { SettingsCacheModule } from './settings-cache/settings-cache.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, envFilePath: '.env' }),

    // ── BullMQ / Redis (global) ──────────────────────────────────────────────
    BullModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (config: ConfigService) => ({
        connection: {
          host: config.get<string>('REDIS_HOST', 'localhost'),
          port: config.get<number>('REDIS_PORT', 6379),
          password: config.get<string>('REDIS_PASSWORD'),
        },
      }),
      inject: [ConfigService],
    }),

    PrismaModule,
    AuthModule,
    UsersModule,
    ApplicationsModule,
    InfrastructureAssetsModule,
    CloudAccountsModule,
    CloudResourcesModule,
    SecurityRequestsModule,
    VulnerabilitiesModule,
    SlaModule,
    DashboardModule,
    ReportsModule,
    SettingsModule,
    ScanFindingsModule,
    ContinuousScanModule,
    FindingsModule,
    NotificationsModule,
    AIModule,
    ComplianceModule,
    SettingsCacheModule,
    // ── Future modules ───────────────────────────────────────────────────────
  ],
})
export class AppModule {}

