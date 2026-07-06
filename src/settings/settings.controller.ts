import {
  Controller,
  Get,
  Post,
  Patch,
  Param,
  Query,
  Body,
  Req,
  UseGuards,
  ParseUUIDPipe,
  HttpCode,
  HttpStatus,
  ParseEnumPipe,
  ParseIntPipe,
} from '@nestjs/common';
import { Request } from 'express';
import { Severity, UserRole } from '@prisma/client';
import { SettingsService } from './settings.service';
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
} from './dto/settings.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

// ── Role sets ──────────────────────────────────────────────────────────────────
const ALL_ROLES = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
  UserRole.APPLICATION_OWNER,
  UserRole.INFRASTRUCTURE_OWNER,
  UserRole.READ_ONLY,
];

const LEAD_ONLY = [UserRole.SECURITY_LEAD];

const LEAD_AND_ANALYST = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
];

// =============================================================================
// SETTINGS CONTROLLER
// All routes under /settings (global prefix: /api/v1)
// =============================================================================

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('settings')
export class SettingsController {
  constructor(private readonly settingsService: SettingsService) {}

  // ── actor helper ─────────────────────────────────────────────────────────────
  private actor(req: Request): { id: string; name: string } {
    const u = req.user as { id: string; name: string };
    return { id: u.id, name: u.name };
  }

  // ==========================================================================
  // SECTION 1 – MY PROFILE
  // ==========================================================================

  /**
   * GET /settings/profile
   * Returns the authenticated user's profile.
   * Accessible to all roles.
   */
  @Get('profile')
  @Roles(...ALL_ROLES)
  getProfile(@Req() req: Request) {
    const user = req.user as { id: string };
    return this.settingsService.getProfile(user.id);
  }

  /**
   * PATCH /settings/profile
   * Update name and/or department. Role cannot be modified here.
   */
  @Patch('profile')
  @Roles(...ALL_ROLES)
  updateProfile(@Body() dto: UpdateProfileDto, @Req() req: Request) {
    const user = req.user as { id: string };
    return this.settingsService.updateProfile(user.id, dto, this.actor(req));
  }

  /**
   * PATCH /settings/profile/change-password
   * Requires current password verification. Bcrypt hashed.
   */
  @Patch('profile/change-password')
  @Roles(...ALL_ROLES)
  @HttpCode(HttpStatus.OK)
  changePassword(@Body() dto: ChangePasswordDto, @Req() req: Request) {
    const user = req.user as { id: string };
    return this.settingsService.changePassword(user.id, dto, this.actor(req));
  }

  // ==========================================================================
  // SECTION 2 – SLA CONFIGURATION
  // ==========================================================================

  /**
   * GET /settings/sla
   * Returns all 5 SLA policies.
   * Accessible to all roles.
   */
  @Get('sla')
  @Roles(...ALL_ROLES)
  getSlaConfig() {
    return this.settingsService.getSlaConfig();
  }

  /**
   * PATCH /settings/sla/:severity
   * Update SLA days for a specific severity.
   * SECURITY_LEAD only.
   *
   * Params: severity = CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
   * Body:   { slaDays: number, description?: string }
   */
  @Patch('sla/:severity')
  @Roles(...LEAD_ONLY)
  updateSlaConfig(
    @Param('severity', new ParseEnumPipe(Severity)) severity: Severity,
    @Body() dto: UpdateSlaDto,
    @Req() req: Request,
  ) {
    return this.settingsService.updateSlaConfig(severity, dto, this.actor(req));
  }

  // ==========================================================================
  // SECTION 3 – INTEGRATIONS
  // ==========================================================================

  /**
   * GET /settings/integrations
   * Returns integration settings. API keys are masked.
   * Accessible to all roles.
   */
  @Get('integrations')
  @Roles(...ALL_ROLES)
  getIntegrations() {
    return this.settingsService.getIntegrations();
  }

  /**
   * PATCH /settings/integrations
   * Update integration settings (API URLs, keys, enable/disable flags).
   * SECURITY_LEAD only.
   *
   * Body: UpdateIntegrationsDto (all fields optional)
   */
  @Patch('integrations')
  @Roles(...LEAD_ONLY)
  updateIntegrations(@Body() dto: UpdateIntegrationsDto, @Req() req: Request) {
    return this.settingsService.updateIntegrations(dto, this.actor(req));
  }

  // ==========================================================================
  // SECTION 4 – AUDIT LOGS
  // ==========================================================================

  /**
   * GET /settings/audit-logs
   * Paginated, filtered audit log viewer.
   * Accessible to SECURITY_LEAD and SECURITY_ANALYST.
   *
   * Query: actor?, entityType?, action?, startDate?, endDate?, page?, limit?
   */
  @Get('audit-logs')
  @Roles(...LEAD_AND_ANALYST)
  getAuditLogs(@Query() filter: AuditLogFilterDto) {
    return this.settingsService.getAuditLogs(filter);
  }

  // ==========================================================================
  // SECTION 5 – USER MANAGEMENT
  // ==========================================================================

  /**
   * GET /settings/users
   * Paginated list of all users.
   * SECURITY_LEAD only.
   *
   * Query: page?, limit?
   */
  @Get('users')
  @Roles(...LEAD_ONLY)
  listUsers(
    @Query('page', new ParseIntPipe({ optional: true })) page?: number,
    @Query('limit', new ParseIntPipe({ optional: true })) limit?: number,
  ) {
    return this.settingsService.listUsers(page, limit);
  }

  /**
   * GET /settings/users/:id
   * Get a single user by ID.
   * SECURITY_LEAD only.
   */
  @Get('users/:id')
  @Roles(...LEAD_ONLY)
  getUser(@Param('id', ParseUUIDPipe) id: string) {
    return this.settingsService.getUser(id);
  }

  /**
   * POST /settings/users
   * Create a new platform user.
   * SECURITY_LEAD only.
   *
   * Body: { email, name, password, role, staffId?, department? }
   */
  @Post('users')
  @Roles(...LEAD_ONLY)
  createUser(@Body() dto: CreateUserDto, @Req() req: Request) {
    return this.settingsService.createUser(dto, this.actor(req));
  }

  /**
   * PATCH /settings/users/:id
   * Update user details (name, role, department, staffId).
   * SECURITY_LEAD only.
   */
  @Patch('users/:id')
  @Roles(...LEAD_ONLY)
  updateUser(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserDto,
    @Req() req: Request,
  ) {
    return this.settingsService.updateUser(id, dto, this.actor(req));
  }

  /**
   * PATCH /settings/users/:id/activate
   * Activate a deactivated user account.
   * SECURITY_LEAD only.
   */
  @Patch('users/:id/activate')
  @Roles(...LEAD_ONLY)
  @HttpCode(HttpStatus.OK)
  activateUser(@Param('id', ParseUUIDPipe) id: string, @Req() req: Request) {
    return this.settingsService.activateUser(id, this.actor(req));
  }

  /**
   * PATCH /settings/users/:id/deactivate
   * Deactivate a user (soft disable — isActive=false). Does not delete.
   * SECURITY_LEAD only. Cannot self-deactivate.
   */
  @Patch('users/:id/deactivate')
  @Roles(...LEAD_ONLY)
  @HttpCode(HttpStatus.OK)
  deactivateUser(@Param('id', ParseUUIDPipe) id: string, @Req() req: Request) {
    return this.settingsService.deactivateUser(id, this.actor(req));
  }

  // ==========================================================================
  // SECTION 6 – PLATFORM SETTINGS
  // ==========================================================================

  /**
   * GET /settings/platform
   * Returns GENERAL, REPORTING, NOTIFICATIONS platform settings.
   * Accessible to all roles.
   */
  @Get('platform')
  @Roles(...ALL_ROLES)
  getPlatformSettings() {
    return this.settingsService.getPlatformSettings();
  }

  /**
   * PATCH /settings/platform
   * Update one or more platform settings by key.
   * Respects isEditable flag — non-editable settings throw 403.
   * SECURITY_LEAD only.
   *
   * Body: { settings: { "general.platformName": "Sentinel SLM" } }
   */
  @Patch('platform')
  @Roles(...LEAD_ONLY)
  updatePlatformSettings(@Body() dto: PlatformSettingsBatchDto, @Req() req: Request) {
    return this.settingsService.updatePlatformSettings(dto, this.actor(req));
  }

  // ==========================================================================
  // SECTION 7 – SECURITY SETTINGS
  // ==========================================================================

  /**
   * GET /settings/security
   * Returns security configuration (JWT expiry, login attempts, upload size).
   * All roles can view.
   */
  @Get('security')
  @Roles(...ALL_ROLES)
  getSecuritySettings() {
    return this.settingsService.getSecuritySettings();
  }

  /**
   * PATCH /settings/security
   * Update security settings.
   * SECURITY_LEAD only.
   *
   * Body: { jwtExpiry?, maxLoginAttempts?, maxUploadSizeMb? }
   */
  @Patch('security')
  @Roles(...LEAD_ONLY)
  updateSecuritySettings(@Body() dto: UpdateSecuritySettingsDto, @Req() req: Request) {
    return this.settingsService.updateSecuritySettings(dto, this.actor(req));
  }
}
