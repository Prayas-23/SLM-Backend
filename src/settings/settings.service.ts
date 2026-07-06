import {
  Injectable,
  NotFoundException,
  BadRequestException,
  ConflictException,
  ForbiddenException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PasswordService } from '../common/services/password.service';
import { NotificationsService } from '../notifications/notifications.service';
import { AIService } from '../ai/ai.service';
import { SettingsCacheService } from '../settings-cache/settings-cache.service';
import {
  UpdateProfileDto,
  ChangePasswordDto,
  UpdateSlaDto,
  UpdateIntegrationsDto,
  AuditLogFilterDto,
  CreateUserDto,
  UpdateUserDto,
  PlatformSettingsBatchDto,
  UpdateSecuritySettingsDto,
  SlaConfigResponse,
  UserResponse,
  PlatformSettingResponse,
  INTEGRATION_KEYS,
  SECRET_KEYS,
  SECURITY_KEYS,
} from './dto/settings.dto';
import {
  AuditAction,
  AuditEntityType,
  Severity,
  SettingCategory,
  SettingDataType,
  UserRole,
} from '@prisma/client';

// ── Shared user select ─────────────────────────────────────────────────────────
const USER_SELECT = {
  id: true, email: true, name: true, staffId: true,
  department: true, role: true, isActive: true,
  lastLoginAt: true, createdAt: true, updatedAt: true,
} as const;

// ── PlatformSetting select ────────────────────────────────────────────────────
const SETTING_SELECT = {
  id: true, category: true, key: true, value: true,
  dataType: true, label: true, description: true,
  isEditable: true, updatedAt: true,
} as const;

// ── Default SLA days ──────────────────────────────────────────────────────────
const DEFAULT_SLA_DAYS: Record<Severity, number> = {
  CRITICAL: 30, HIGH: 45, MEDIUM: 90, LOW: 180, INFORMATIONAL: 365,
};

@Injectable()
export class SettingsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwordService: PasswordService,
    private readonly notifications: NotificationsService,
    private readonly aiService: AIService,
    private readonly settingsCache: SettingsCacheService,
  ) {}

  // ── Audit helper ────────────────────────────────────────────────────────────

  private async audit(params: {
    actorId: string;
    actorName: string;
    entityType: AuditEntityType;
    entityId: string;
    action: AuditAction;
    before?: unknown;
    after?: unknown;
    metadata?: unknown;
  }) {
    await this.prisma.auditLog.create({
      data: {
        actorId: params.actorId,
        actorName: params.actorName,
        entityType: params.entityType,
        entityId: params.entityId,
        action: params.action,
        before: params.before as never ?? undefined,
        after: params.after as never ?? undefined,
        metadata: params.metadata as never ?? undefined,
      },
    });
  }

  // ==========================================================================
  // SECTION 1 – MY PROFILE
  // ==========================================================================

  async getProfile(userId: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        ...USER_SELECT,
        avatarUrl: true,
      },
    });
    if (!user) throw new NotFoundException('User not found.');
    return user;
  }

  async updateProfile(
    userId: string,
    dto: UpdateProfileDto,
    actor: { id: string; name: string },
  ) {
    const existing = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
    });
    if (!existing) throw new NotFoundException('User not found.');

    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: {
        ...(dto.name && { name: dto.name }),
        ...(dto.department !== undefined && { department: dto.department }),
      },
      select: { ...USER_SELECT, avatarUrl: true },
    });

    await this.audit({
      actorId: actor.id,
      actorName: actor.name,
      entityType: AuditEntityType.USER,
      entityId: userId,
      action: AuditAction.UPDATED,
      before: { name: existing.name, department: existing.department },
      after: { name: updated.name, department: updated.department },
      metadata: { event: 'PROFILE_UPDATED' },
    });

    return updated;
  }

  async changePassword(
    userId: string,
    dto: ChangePasswordDto,
    actor: { id: string; name: string },
  ) {
    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException('New password and confirm password do not match.');
    }

    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
    });
    if (!user) throw new NotFoundException('User not found.');

    const currentValid = await this.passwordService.compare(
      dto.currentPassword,
      user.passwordHash,
    );
    if (!currentValid) {
      throw new BadRequestException('Current password is incorrect.');
    }

    const newHash = await this.passwordService.hash(dto.newPassword);
    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash: newHash },
    });

    await this.audit({
      actorId: actor.id,
      actorName: actor.name,
      entityType: AuditEntityType.USER,
      entityId: userId,
      action: AuditAction.UPDATED,
      metadata: { event: 'PASSWORD_CHANGED' },
    });

    return { message: 'Password changed successfully.' };
  }

  // ==========================================================================
  // SECTION 2 – SLA CONFIGURATION
  // ==========================================================================

  async getSlaConfig(): Promise<SlaConfigResponse[]> {
    const policies = await this.prisma.slaPolicy.findMany({
      orderBy: { severity: 'asc' },
    });

    // Ensure all 5 severities are represented — seed defaults if missing
    const existing = new Map(policies.map((p) => [p.severity, p]));
    const result: SlaConfigResponse[] = [];

    for (const severity of Object.values(Severity)) {
      if (existing.has(severity)) {
        const p = existing.get(severity)!;
        result.push({
          id: p.id, severity: p.severity, slaDays: p.slaDays,
          description: p.description, isActive: p.isActive, updatedAt: p.updatedAt,
        });
      } else {
        // Auto-create missing policy with default
        const created = await this.prisma.slaPolicy.create({
          data: { severity, slaDays: DEFAULT_SLA_DAYS[severity] },
        });
        result.push({
          id: created.id, severity: created.severity, slaDays: created.slaDays,
          description: created.description, isActive: created.isActive, updatedAt: created.updatedAt,
        });
      }
    }

    return result;
  }

  async updateSlaConfig(
    severity: Severity,
    dto: UpdateSlaDto,
    actor: { id: string; name: string },
  ): Promise<SlaConfigResponse> {
    const existing = await this.prisma.slaPolicy.findUnique({ where: { severity } });

    let policy;
    if (existing) {
      policy = await this.prisma.slaPolicy.update({
        where: { severity },
        data: { slaDays: dto.slaDays, ...(dto.description !== undefined && { description: dto.description }) },
      });
    } else {
      policy = await this.prisma.slaPolicy.create({
        data: { severity, slaDays: dto.slaDays, description: dto.description },
      });
    }

    await this.audit({
      actorId: actor.id,
      actorName: actor.name,
      entityType: AuditEntityType.USER,
      entityId: policy.id,
      action: AuditAction.UPDATED,
      before: existing ? { slaDays: existing.slaDays } : null,
      after: { severity, slaDays: dto.slaDays },
      metadata: { event: 'SLA_UPDATED', severity },
    });

    return {
      id: policy.id, severity: policy.severity, slaDays: policy.slaDays,
      description: policy.description, isActive: policy.isActive, updatedAt: policy.updatedAt,
    };
  }

  // ==========================================================================
  // SECTION 3 – INTEGRATIONS
  // ==========================================================================

  async getIntegrations(): Promise<Record<string, unknown>> {
    const settings = await this.prisma.platformSetting.findMany({
      where: { category: SettingCategory.INTEGRATIONS },
      select: SETTING_SELECT,
    });

    const map: Record<string, string> = {};
    for (const s of settings) {
      // Mask secrets
      map[s.key] = SECRET_KEYS.has(s.key) ? this.maskSecret(s.value) : s.value;
    }

    return {
      cloudsek: {
        apiUrl: map['integrations.cloudsek.apiUrl'] ?? '',
        apiKey: map['integrations.cloudsek.apiKey'] ?? '',
        enabled: map['integrations.cloudsek.enabled'] === 'true',
      },
      qualys: {
        apiUrl: map['integrations.qualys.apiUrl'] ?? '',
        apiKey: map['integrations.qualys.apiKey'] ?? '',
        enabled: map['integrations.qualys.enabled'] === 'true',
      },
      aiProvider: {
        apiUrl: map['integrations.aiProvider.apiUrl'] ?? '',
        apiKey: map['integrations.aiProvider.apiKey'] ?? '',
        enabled: map['integrations.aiProvider.enabled'] === 'true',
      },
    };
  }

  async updateIntegrations(
    dto: UpdateIntegrationsDto,
    actor: { id: string; name: string },
  ): Promise<Record<string, unknown>> {
    const updates: Record<string, string> = {};

    if (dto.cloudsekApiUrl !== undefined) updates['integrations.cloudsek.apiUrl'] = dto.cloudsekApiUrl;
    if (dto.cloudsekApiKey !== undefined) updates['integrations.cloudsek.apiKey'] = dto.cloudsekApiKey;
    if (dto.cloudsekEnabled !== undefined) updates['integrations.cloudsek.enabled'] = String(dto.cloudsekEnabled);
    if (dto.qualysApiUrl !== undefined) updates['integrations.qualys.apiUrl'] = dto.qualysApiUrl;
    if (dto.qualysApiKey !== undefined) updates['integrations.qualys.apiKey'] = dto.qualysApiKey;
    if (dto.qualysEnabled !== undefined) updates['integrations.qualys.enabled'] = String(dto.qualysEnabled);
    if (dto.aiProviderApiUrl !== undefined) updates['integrations.aiProvider.apiUrl'] = dto.aiProviderApiUrl;
    if (dto.aiProviderApiKey !== undefined) updates['integrations.aiProvider.apiKey'] = dto.aiProviderApiKey;
    if (dto.aiProviderEnabled !== undefined) updates['integrations.aiProvider.enabled'] = String(dto.aiProviderEnabled);

    await this.upsertSettings(updates, SettingCategory.INTEGRATIONS);

    await this.audit({
      actorId: actor.id,
      actorName: actor.name,
      entityType: AuditEntityType.USER,
      entityId: actor.id,
      action: AuditAction.UPDATED,
      after: { keys: Object.keys(updates) },
      metadata: { event: 'INTEGRATIONS_UPDATED' },
    });

    await this.settingsCache.refresh();

    return this.getIntegrations();
  }

  private maskSecret(value: string): string {
    if (!value || value.length < 8) return '••••••••';
    return value.slice(0, 4) + '••••••••' + value.slice(-4);
  }

  private async upsertSettings(
    updates: Record<string, string>,
    category: SettingCategory,
  ) {
    for (const [key, value] of Object.entries(updates)) {
      await this.prisma.platformSetting.upsert({
        where: { key },
        create: { category, key, value, dataType: SettingDataType.STRING },
        update: { value },
      });
    }
  }

  // ==========================================================================
  // SECTION 4 – AUDIT LOGS
  // ==========================================================================

  async getAuditLogs(filter: AuditLogFilterDto) {
    const { page = 1, limit = 20, actor, entityType, action, startDate, endDate } = filter;
    const skip = (page - 1) * limit;

    const where: Record<string, unknown> = {};
    if (actor) {
      where.OR = [
        { actorName: { contains: actor, mode: 'insensitive' } },
        { actorId: actor },
      ];
    }
    if (entityType) where.entityType = entityType;
    if (action) where.action = action;
    if (startDate || endDate) {
      where.timestamp = {
        ...(startDate && { gte: new Date(startDate) }),
        ...(endDate && { lte: new Date(endDate) }),
      };
    }

    const [data, total] = await this.prisma.$transaction([
      this.prisma.auditLog.findMany({
        where,
        select: {
          id: true, actorId: true, actorName: true,
          entityType: true, entityId: true, action: true,
          before: true, after: true, metadata: true, timestamp: true,
          actor: { select: { name: true, email: true, role: true } },
        },
        orderBy: { timestamp: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.auditLog.count({ where }),
    ]);

    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  // ==========================================================================
  // SECTION 5 – USER MANAGEMENT
  // ==========================================================================

  async listUsers(page = 1, limit = 20): Promise<{ data: UserResponse[]; total: number; page: number; limit: number; totalPages: number }> {
    const skip = (page - 1) * limit;
    const [data, total] = await this.prisma.$transaction([
      this.prisma.user.findMany({
        where: { deletedAt: null },
        select: USER_SELECT,
        orderBy: { createdAt: 'desc' },
        skip, take: limit,
      }),
      this.prisma.user.count({ where: { deletedAt: null } }),
    ]);
    return { data: data as UserResponse[], total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async getUser(id: string): Promise<UserResponse> {
    const user = await this.prisma.user.findFirst({
      where: { id, deletedAt: null },
      select: USER_SELECT,
    });
    if (!user) throw new NotFoundException(`User '${id}' not found.`);
    return user as UserResponse;
  }

  async createUser(
    dto: CreateUserDto,
    actor: { id: string; name: string },
  ): Promise<UserResponse> {
    const exists = await this.prisma.user.findFirst({
      where: { email: dto.email, deletedAt: null },
    });
    if (exists) throw new ConflictException('Email is already in use.');

    if (dto.staffId) {
      const staffExists = await this.prisma.user.findFirst({
        where: { staffId: dto.staffId, deletedAt: null },
      });
      if (staffExists) throw new ConflictException('Staff ID is already in use.');
    }

    const passwordHash = await this.passwordService.hash(dto.password);

    const user = await this.prisma.user.create({
      data: {
        email: dto.email,
        name: dto.name,
        role: dto.role,
        staffId: dto.staffId,
        department: dto.department,
        passwordHash,
      },
      select: USER_SELECT,
    });

    await this.audit({
      actorId: actor.id,
      actorName: actor.name,
      entityType: AuditEntityType.USER,
      entityId: user.id,
      action: AuditAction.CREATED,
      after: { email: user.email, role: user.role, name: user.name },
      metadata: { event: 'USER_CREATED' },
    });

    return user as UserResponse;
  }

  async updateUser(
    id: string,
    dto: UpdateUserDto,
    actor: { id: string; name: string },
  ): Promise<UserResponse> {
    const existing = await this.prisma.user.findFirst({
      where: { id, deletedAt: null },
    });
    if (!existing) throw new NotFoundException(`User '${id}' not found.`);

    const updated = await this.prisma.user.update({
      where: { id },
      data: {
        ...(dto.name && { name: dto.name }),
        ...(dto.role && { role: dto.role }),
        ...(dto.department !== undefined && { department: dto.department }),
        ...(dto.staffId !== undefined && { staffId: dto.staffId }),
      },
      select: USER_SELECT,
    });

    await this.audit({
      actorId: actor.id,
      actorName: actor.name,
      entityType: AuditEntityType.USER,
      entityId: id,
      action: AuditAction.UPDATED,
      before: { name: existing.name, role: existing.role, department: existing.department },
      after: { name: updated.name, role: updated.role, department: updated.department },
      metadata: { event: 'USER_UPDATED' },
    });

    return updated as UserResponse;
  }

  async activateUser(
    id: string,
    actor: { id: string; name: string },
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findFirst({ where: { id, deletedAt: null } });
    if (!user) throw new NotFoundException(`User '${id}' not found.`);
    if (user.isActive) throw new BadRequestException('User is already active.');

    await this.prisma.user.update({ where: { id }, data: { isActive: true } });

    await this.audit({
      actorId: actor.id, actorName: actor.name,
      entityType: AuditEntityType.USER, entityId: id,
      action: AuditAction.UPDATED,
      after: { isActive: true },
      metadata: { event: 'USER_ACTIVATED' },
    });

    return { message: 'User activated successfully.' };
  }

  async deactivateUser(
    id: string,
    actor: { id: string; name: string },
  ): Promise<{ message: string }> {
    const user = await this.prisma.user.findFirst({ where: { id, deletedAt: null } });
    if (!user) throw new NotFoundException(`User '${id}' not found.`);
    if (!user.isActive) throw new BadRequestException('User is already inactive.');

    // Prevent self-deactivation
    if (id === actor.id) {
      throw new ForbiddenException('You cannot deactivate your own account.');
    }

    await this.prisma.user.update({ where: { id }, data: { isActive: false } });

    await this.audit({
      actorId: actor.id, actorName: actor.name,
      entityType: AuditEntityType.USER, entityId: id,
      action: AuditAction.UPDATED,
      after: { isActive: false },
      metadata: { event: 'USER_DEACTIVATED' },
    });

    return { message: 'User deactivated successfully.' };
  }

  // ==========================================================================
  // SECTION 6 – PLATFORM SETTINGS
  // ==========================================================================

  async getPlatformSettings(): Promise<PlatformSettingResponse[]> {
    return this.prisma.platformSetting.findMany({
      where: {
        category: {
          in: [
            SettingCategory.GENERAL,
            SettingCategory.REPORTING,
            SettingCategory.NOTIFICATIONS,
            SettingCategory.AI,
          ],
        },
      },
      select: SETTING_SELECT,
      orderBy: [{ category: 'asc' }, { key: 'asc' }],
    }) as Promise<PlatformSettingResponse[]>;
  }

  async updatePlatformSettings(
    dto: PlatformSettingsBatchDto,
    actor: { id: string; name: string },
  ): Promise<PlatformSettingResponse[]> {
    const keys = Object.keys(dto.settings);
    if (keys.length === 0) throw new BadRequestException('No settings provided.');

    for (const [key, value] of Object.entries(dto.settings)) {
      const existing = await this.prisma.platformSetting.findUnique({ where: { key } });

      if (existing) {
        if (!existing.isEditable) {
          throw new ForbiddenException(`Setting '${key}' is not editable.`);
        }
        await this.prisma.platformSetting.update({
          where: { key },
          data: { value, updatedById: actor.id },
        });
      } else {
        // New settings can only be created within allowed categories
        throw new BadRequestException(`Setting key '${key}' does not exist.`);
      }
    }

    await this.audit({
      actorId: actor.id, actorName: actor.name,
      entityType: AuditEntityType.USER, entityId: actor.id,
      action: AuditAction.UPDATED,
      after: dto.settings,
      metadata: { event: 'PLATFORM_SETTINGS_UPDATED', keys },
    });

    // Dynamic notification config refresh
    const hasNotificationKeys = keys.some((k) => k.startsWith('notifications.'));
    if (hasNotificationKeys) {
      await this.notifications.refreshConfig();
    }

    // Dynamic AI config refresh — no restart required
    const hasAiKeys = keys.some((k) => k.startsWith('ai.'));
    if (hasAiKeys) {
      await this.aiService.refreshConfig();
    }

    await this.settingsCache.refresh();

    return this.getPlatformSettings();
  }

  // ==========================================================================
  // SECTION 7 – SECURITY SETTINGS
  // ==========================================================================

  async getSecuritySettings(): Promise<Record<string, unknown>> {
    const settings = await this.prisma.platformSetting.findMany({
      where: { category: SettingCategory.SECURITY },
      select: SETTING_SELECT,
    });

    const map = new Map(settings.map((s) => [s.key, s.value]));

    return {
      jwtExpiry: map.get('security.jwtExpiry') ?? '1h',
      maxLoginAttempts: parseInt(map.get('security.maxLoginAttempts') ?? '5', 10),
      maxUploadSizeMb: parseInt(map.get('security.maxUploadSizeMb') ?? '20', 10),
    };
  }

  async updateSecuritySettings(
    dto: UpdateSecuritySettingsDto,
    actor: { id: string; name: string },
  ): Promise<Record<string, unknown>> {
    const updates: Record<string, string> = {};

    if (dto.jwtExpiry !== undefined) updates['security.jwtExpiry'] = dto.jwtExpiry;
    if (dto.maxLoginAttempts !== undefined) updates['security.maxLoginAttempts'] = String(dto.maxLoginAttempts);
    if (dto.maxUploadSizeMb !== undefined) updates['security.maxUploadSizeMb'] = String(dto.maxUploadSizeMb);

    if (Object.keys(updates).length === 0) {
      throw new BadRequestException('No security settings provided.');
    }

    await this.upsertSettings(updates, SettingCategory.SECURITY);

    await this.audit({
      actorId: actor.id, actorName: actor.name,
      entityType: AuditEntityType.USER, entityId: actor.id,
      action: AuditAction.UPDATED,
      after: updates,
      metadata: { event: 'SECURITY_SETTINGS_UPDATED' },
    });

    await this.settingsCache.refresh();

    return this.getSecuritySettings();
  }
}
