import {
  IsString,
  IsEnum,
  IsOptional,
  IsDateString,
  IsArray,
  IsEmail,
  IsBoolean,
  IsNotEmpty,
  MaxLength,
  ArrayNotEmpty,
  IsObject,
} from 'class-validator';
import { Environment, ReportStatus, Severity, CvsAssignmentMethod } from '@prisma/client';

// ── Report Types ───────────────────────────────────────────────────────────────

export enum ReportType {
  VULNERABILITIES       = 'VULNERABILITIES',
  SECURITY_REQUESTS     = 'SECURITY_REQUESTS',
  SLA                   = 'SLA',
  APPLICATIONS          = 'APPLICATIONS',
  INFRASTRUCTURE_ASSETS = 'INFRASTRUCTURE_ASSETS',
  CLOUD_RESOURCES       = 'CLOUD_RESOURCES',
  EXECUTIVE_DASHBOARD   = 'EXECUTIVE_DASHBOARD',
  CONTINUOUS_SCAN_FINDINGS = 'CONTINUOUS_SCAN_FINDINGS',
}

// ── Report Formats ─────────────────────────────────────────────────────────────

export enum ReportFormat {
  CSV  = 'CSV',
  XLSX = 'XLSX',
}

// ── Shared Filter ──────────────────────────────────────────────────────────────

export class ReportFilterDto {
  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  source?: string;

  @IsOptional()
  @IsEnum(CvsAssignmentMethod)
  assignmentMethod?: CvsAssignmentMethod;

  @IsOptional()
  @IsString()
  owner?: string;

  @IsOptional()
  @IsString()
  asset?: string;

  @IsOptional()
  @IsString()
  application?: string;
}

// ── Generate Report ────────────────────────────────────────────────────────────

export class GenerateReportDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(200)
  title: string;

  @IsEnum(ReportType)
  type: ReportType;

  @IsEnum(ReportFormat)
  format: ReportFormat;

  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  source?: string;

  @IsOptional()
  @IsEnum(CvsAssignmentMethod)
  assignmentMethod?: CvsAssignmentMethod;

  @IsOptional()
  @IsString()
  owner?: string;

  @IsOptional()
  @IsString()
  asset?: string;

  @IsOptional()
  @IsString()
  application?: string;

  @IsOptional()
  @IsObject()
  extraFilters?: Record<string, any>;
}

// ── Schedule Report ────────────────────────────────────────────────────────────

export class ScheduleReportDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(200)
  title: string;

  @IsEnum(ReportType)
  type: ReportType;

  @IsEnum(ReportFormat)
  format: ReportFormat;

  /**
   * Standard cron expression — e.g. "0 8 * * 1" for every Monday at 08:00
   */
  @IsString()
  @IsNotEmpty()
  cronExpr: string;

  @IsArray()
  @ArrayNotEmpty()
  @IsEmail({}, { each: true })
  recipients: string[];

  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsEnum(Severity)
  severity?: Severity;

  @IsOptional()
  @IsString()
  status?: string;

  @IsOptional()
  @IsString()
  source?: string;

  @IsOptional()
  @IsEnum(CvsAssignmentMethod)
  assignmentMethod?: CvsAssignmentMethod;

  @IsOptional()
  @IsString()
  owner?: string;

  @IsOptional()
  @IsString()
  asset?: string;

  @IsOptional()
  @IsString()
  application?: string;

  @IsOptional()
  @IsObject()
  extraFilters?: Record<string, any>;
}

// ── Update Schedule ────────────────────────────────────────────────────────────

export class UpdateScheduleDto {
  @IsOptional()
  @IsString()
  @MaxLength(200)
  title?: string;

  @IsOptional()
  @IsString()
  cronExpr?: string;

  @IsOptional()
  @IsEnum(ReportFormat)
  format?: ReportFormat;

  @IsOptional()
  @IsArray()
  @ArrayNotEmpty()
  @IsEmail({}, { each: true })
  recipients?: string[];

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;
}

// ── List Filter ────────────────────────────────────────────────────────────────

export class ListReportsDto {
  @IsOptional()
  @IsEnum(ReportStatus)
  status?: ReportStatus;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;
}

// ── Response Interfaces ────────────────────────────────────────────────────────

export interface ReportResponse {
  id: string;
  title: string;
  status: ReportStatus;
  format: string | null;
  filters: Record<string, unknown> | null;
  url: string | null;
  expiresAt: Date | null;
  generatedAt: Date | null;
  createdAt: Date;
  requestedBy?: { id: string; name: string; email: string } | null;
}

export interface ScheduleResponse {
  id: string;
  title: string;
  cronExpr: string;
  format: string | null;
  filters: Record<string, unknown> | null;
  recipients: string[];
  isActive: boolean;
  lastRunAt: Date | null;
  nextRunAt: Date | null;
  createdAt: Date;
}
