import {
  IsString,
  IsOptional,
  IsEmail,
  IsEnum,
  IsInt,
  IsBoolean,
  IsDateString,
  IsNotEmpty,
  MaxLength,
  MinLength,
  Min,
  Max,
  IsPositive,
  IsObject,
} from 'class-validator';
import { Type } from 'class-transformer';
import { UserRole, AuditEntityType, AuditAction, Severity, SettingDataType } from '@prisma/client';

// =============================================================================
// SECTION 1 – MY PROFILE
// =============================================================================

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;
}

export class ChangePasswordDto {
  @IsString()
  @IsNotEmpty()
  currentPassword: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(128)
  newPassword: string;

  @IsString()
  @IsNotEmpty()
  confirmPassword: string;
}

// =============================================================================
// SECTION 2 – SLA CONFIGURATION
// =============================================================================

export class UpdateSlaDto {
  @IsInt()
  @IsPositive()
  @Min(1)
  @Max(3650)
  slaDays: number;

  @IsOptional()
  @IsString()
  @MaxLength(300)
  description?: string;
}

export interface SlaConfigResponse {
  id: string;
  severity: Severity;
  slaDays: number;
  description: string | null;
  isActive: boolean;
  updatedAt: Date;
}

// =============================================================================
// SECTION 3 – INTEGRATIONS
// =============================================================================

export class UpdateIntegrationsDto {
  /** CloudSEK integration */
  @IsOptional()
  @IsString()
  @MaxLength(500)
  cloudsekApiUrl?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  cloudsekApiKey?: string;

  @IsOptional()
  @IsBoolean()
  cloudsekEnabled?: boolean;

  /** Qualys integration */
  @IsOptional()
  @IsString()
  @MaxLength(500)
  qualysApiUrl?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  qualysApiKey?: string;

  @IsOptional()
  @IsBoolean()
  qualysEnabled?: boolean;

  /** AI Provider (TBD) */
  @IsOptional()
  @IsString()
  @MaxLength(500)
  aiProviderApiUrl?: string;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  aiProviderApiKey?: string;

  @IsOptional()
  @IsBoolean()
  aiProviderEnabled?: boolean;
}

// Integration setting keys (matches PlatformSetting.key values)
export const INTEGRATION_KEYS = [
  'integrations.cloudsek.apiUrl',
  'integrations.cloudsek.apiKey',
  'integrations.cloudsek.enabled',
  'integrations.qualys.apiUrl',
  'integrations.qualys.apiKey',
  'integrations.qualys.enabled',
  'integrations.aiProvider.apiUrl',
  'integrations.aiProvider.apiKey',
  'integrations.aiProvider.enabled',
] as const;

// Secret keys that must be masked in responses
export const SECRET_KEYS = new Set([
  'integrations.cloudsek.apiKey',
  'integrations.qualys.apiKey',
  'integrations.aiProvider.apiKey',
]);

// =============================================================================
// SECTION 4 – AUDIT LOGS
// =============================================================================

export class AuditLogFilterDto {
  @IsOptional()
  @IsString()
  actor?: string;

  @IsOptional()
  @IsEnum(AuditEntityType)
  entityType?: AuditEntityType;

  @IsOptional()
  @IsEnum(AuditAction)
  action?: AuditAction;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page?: number = 1;

  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number = 20;
}

// =============================================================================
// SECTION 5 – USER MANAGEMENT
// =============================================================================

export class CreateUserDto {
  @IsEmail()
  email: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(128)
  password: string;

  @IsEnum(UserRole)
  role: UserRole;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  staffId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;
}

export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(100)
  name?: string;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  department?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  staffId?: string;
}

// =============================================================================
// SECTION 6 – PLATFORM SETTINGS
// =============================================================================

export class UpdatePlatformSettingDto {
  /** key→value map of settings to update */
  [key: string]: string;
}

export class PlatformSettingsBatchDto {
  @IsObject()
  @IsNotEmpty()
  settings: Record<string, string>;
}

// =============================================================================
// SECTION 7 – SECURITY SETTINGS
// =============================================================================

export class UpdateSecuritySettingsDto {
  @IsOptional()
  @IsString()
  @MaxLength(20)
  jwtExpiry?: string;        // e.g. "1h", "2h", "30m"

  @IsOptional()
  @IsInt()
  @Min(3)
  @Max(20)
  @Type(() => Number)
  maxLoginAttempts?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  @Type(() => Number)
  maxUploadSizeMb?: number;
}

// Security setting keys
export const SECURITY_KEYS = [
  'security.jwtExpiry',
  'security.maxLoginAttempts',
  'security.maxUploadSizeMb',
] as const;

// =============================================================================
// SHARED RESPONSE INTERFACES
// =============================================================================

export interface UserResponse {
  id: string;
  email: string;
  name: string;
  staffId: string | null;
  department: string | null;
  role: UserRole;
  isActive: boolean;
  lastLoginAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

export interface PlatformSettingResponse {
  id: string;
  category: string;
  key: string;
  value: string;
  dataType: SettingDataType;
  label: string | null;
  description: string | null;
  isEditable: boolean;
  updatedAt: Date;
}
