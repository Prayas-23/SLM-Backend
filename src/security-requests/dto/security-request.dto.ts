import {
  IsEnum, IsNotEmpty, IsOptional, IsString, IsDateString,
  IsInt, Min, IsUrl,
} from 'class-validator';
import { Type } from 'class-transformer';
import {
  RequestSource, RequestStatus, Environment,
} from '@prisma/client';
import { PaginationDto } from '../../common/dto/pagination.dto';

// ── Create ────────────────────────────────────────────────────────────────────

export class CreateSecurityRequestDto {
  @IsEnum(RequestSource)
  source: RequestSource;

  @IsEnum(Environment)
  @IsOptional()
  environment?: Environment;

  @IsOptional()
  @IsString()
  targetAppId?: string;

  @IsOptional()
  @IsString()
  targetInfraId?: string;

  /** VAPT: SecureLayer7 / Qualys | Bug Bounty: HackerOne / BugCrowd | Red Team: Cobalt.io */
  @IsOptional()
  @IsString()
  partner?: string;

  @IsOptional()
  @IsUrl()
  programmeUrl?: string;

  @IsOptional()
  @IsString()
  assignedToId?: string;

  /** Channel-specific metadata blob */
  @IsOptional()
  assessmentMeta?: Record<string, unknown>;
}

// ── Update ────────────────────────────────────────────────────────────────────

export class UpdateSecurityRequestDto {
  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  @IsOptional()
  @IsString()
  targetAppId?: string;

  @IsOptional()
  @IsString()
  targetInfraId?: string;

  @IsOptional()
  @IsString()
  partner?: string;

  @IsOptional()
  @IsUrl()
  programmeUrl?: string;

  @IsOptional()
  @IsString()
  assignedToId?: string;

  @IsOptional()
  @IsInt() @Min(0)
  totalFindings?: number;

  @IsOptional()
  @IsInt() @Min(0)
  openFindings?: number;

  @IsOptional()
  @IsInt() @Min(0)
  critFindings?: number;

  @IsOptional()
  @IsInt() @Min(0)
  highFindings?: number;

  @IsOptional()
  @IsInt() @Min(0)
  slaCompliance?: number;

  @IsOptional()
  assessmentMeta?: Record<string, unknown>;
}

// ── Status Transition ─────────────────────────────────────────────────────────

export class UpdateRequestStatusDto {
  @IsEnum(RequestStatus)
  status: RequestStatus;

  @IsOptional()
  @IsString()
  remarks?: string;
}

// ── Comment ───────────────────────────────────────────────────────────────────

export class AddCommentDto {
  @IsString()
  @IsNotEmpty()
  body: string;
}

// ── Filter ────────────────────────────────────────────────────────────────────

export class FilterSecurityRequestDto extends PaginationDto {
  @IsOptional()
  @IsEnum(Environment)
  environment?: Environment;

  @IsOptional()
  @IsEnum(RequestSource)
  source?: RequestSource;

  @IsOptional()
  @IsEnum(RequestStatus)
  status?: RequestStatus;

  @IsOptional()
  @IsString()
  targetAppId?: string;

  @IsOptional()
  @IsString()
  targetInfraId?: string;



  @IsOptional()
  @IsString()
  reqId?: string;

  @IsOptional()
  @IsString()
  appName?: string;

  @IsOptional()
  @IsString()
  initiatedBy?: string;

  @IsOptional()
  @IsString()
  assignedTo?: string;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsString()
  sortBy?: string;

  @IsOptional()
  @IsString()
  sortDir?: string;

}
