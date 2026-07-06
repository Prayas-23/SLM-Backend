import { IsEnum, IsNotEmpty, IsOptional, IsString, IsNumber, Min, Max, IsBoolean } from 'class-validator';
import { Type } from 'class-transformer';
import { RequestSource, Severity, FindingStatus } from '@prisma/client';
import { PaginationDto } from '../../common/dto/pagination.dto';

export class CreateFindingDto {
  @IsString() @IsNotEmpty()
  title: string;

  @IsOptional() @IsString()
  description?: string;

  @IsEnum(Severity)
  severity: Severity;

  @IsEnum(RequestSource)
  sourceType: RequestSource;

  @IsOptional() @IsString()
  sourceId?: string;

  @IsOptional() @IsNumber() @Min(0) @Max(10)
  @Type(() => Number)
  cvssScore?: number;

  @IsOptional() @IsString()
  cveId?: string;

  @IsOptional() @IsString()
  recommendation?: string;

  @IsOptional() @IsString()
  evidence?: string;
}

export class UpdateFindingStatusDto {
  @IsEnum(FindingStatus)
  status: FindingStatus;
}

export class FilterFindingDto extends PaginationDto {
  @IsOptional() @IsEnum(RequestSource)
  sourceType?: RequestSource;

  @IsOptional() @IsEnum(Severity)
  severity?: Severity;

  @IsOptional() @IsEnum(FindingStatus)
  status?: FindingStatus;

  @IsOptional() @IsString()
  sourceId?: string;

  @IsOptional() @IsBoolean()
  @Type(() => Boolean)
  convertedToVulnerability?: boolean;
}
