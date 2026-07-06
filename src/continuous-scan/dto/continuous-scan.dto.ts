import {
  IsEnum, IsNotEmpty, IsOptional, IsString,
  IsNumber, Min, Max, IsArray,
} from 'class-validator';
import { Type } from 'class-transformer';
import { Severity } from '@prisma/client';
import { PaginationDto } from '../../common/dto/pagination.dto';

// ── Filter ────────────────────────────────────────────────────────────────────

export class FilterCvsFindingDto extends PaginationDto {
  @IsOptional() @IsString()
  status?: string;

  @IsOptional() @IsEnum(Severity)
  severity?: Severity;

  @IsOptional() @IsString()
  search?: string;

  @IsOptional() @IsString()
  id?: string;

  @IsOptional() @IsString()
  vulnTitle?: string;

  @IsOptional() @IsString()
  asset?: string;

  @IsOptional() @IsString()
  owner?: string;

  @IsOptional() @IsString()
  source?: string;
}

// ── Create (Manual Entry) ─────────────────────────────────────────────────────

export class CreateCvsFindingDto {
  @IsString() @IsNotEmpty()
  vulnTitle: string;

  @IsOptional() @IsString()
  description?: string;

  @IsEnum(Severity)
  severity: Severity;

  @IsOptional() @IsNumber() @Min(0) @Max(10)
  @Type(() => Number)
  cvss?: number;

  @IsOptional() @IsString()
  cve?: string;

  @IsOptional() @IsString()
  assetId?: string;

  @IsOptional() @IsString()
  assetName?: string;

  /** Scanner name — defaults to MANUAL for manual entries */
  @IsOptional() @IsString()
  scannerName?: string;
}

// ── Assign by Asset ───────────────────────────────────────────────────────────

export class AssignByAssetDto {
  /** InfrastructureAsset.id to look up owner and assign findings for */
  @IsString() @IsNotEmpty()
  assetId: string;

  /** Optional: only assign these specific finding IDs. If omitted, assigns all unassigned findings for the asset. */
  @IsOptional() @IsArray() @IsString({ each: true })
  findingIds?: string[];
}

// ── Accept (Promote to SecurityRequest + Vulnerability) ───────────────────────

export class AcceptFindingDto {
  /** Optional assignee for the created Vulnerability */
  @IsOptional() @IsString()
  assignedToId?: string;

  /** Optional additional notes for the Vulnerability record */
  @IsOptional() @IsString()
  notes?: string;
}
