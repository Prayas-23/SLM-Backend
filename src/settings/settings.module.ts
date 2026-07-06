import { Module } from '@nestjs/common';
import { SettingsController } from './settings.controller';
import { SettingsService } from './settings.service';
import { AuthModule } from '../auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { AIModule } from '../ai/ai.module';

/**
 * Settings Module — Phase 2I
 *
 * Provides full platform configuration management for Sentinel SLM.
 *
 * Imports AuthModule to reuse PasswordService (bcrypt hashing)
 * without duplicating the provider.
 *
 * Endpoints (under /api/v1/settings):
 *
 *   SECTION 1 — My Profile
 *     GET    /settings/profile
 *     PATCH  /settings/profile
 *     PATCH  /settings/profile/change-password
 *
 *   SECTION 2 — SLA Configuration
 *     GET    /settings/sla
 *     PATCH  /settings/sla/:severity
 *
 *   SECTION 3 — Integrations
 *     GET    /settings/integrations
 *     PATCH  /settings/integrations
 *
 *   SECTION 4 — Audit Logs
 *     GET    /settings/audit-logs
 *
 *   SECTION 5 — User Management
 *     GET    /settings/users
 *     GET    /settings/users/:id
 *     POST   /settings/users
 *     PATCH  /settings/users/:id
 *     PATCH  /settings/users/:id/activate
 *     PATCH  /settings/users/:id/deactivate
 *
 *   SECTION 6 — Platform Settings
 *     GET    /settings/platform
 *     PATCH  /settings/platform
 *
 *   SECTION 7 — Security Settings
 *     GET    /settings/security
 *     PATCH  /settings/security
 *
 * RBAC Matrix:
 *   SECURITY_LEAD        → full access (all endpoints)
 *   SECURITY_ANALYST     → read all + audit logs (no write)
 *   APPLICATION_OWNER    → profile only
 *   INFRASTRUCTURE_OWNER → profile only
 *   READ_ONLY            → read-only (profile + view settings)
 */
@Module({
  imports: [AuthModule, NotificationsModule, AIModule],
  controllers: [SettingsController],
  providers: [SettingsService],
  exports: [SettingsService],
})
export class SettingsModule {}
