import { IsBoolean, IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { Environment, InfraType } from '@prisma/client';

export class CreateInfrastructureAssetDto {
  @IsString() @IsNotEmpty() serverId: string;
  @IsString() @IsNotEmpty() serverName: string;
  @IsEnum(InfraType) type: InfraType;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() hostname?: string;
  @IsOptional() @IsString() ip?: string;
  @IsOptional() @IsBoolean() publicIp?: boolean;
  @IsOptional() @IsString() location?: string;
  @IsOptional() @IsString() os?: string;
  @IsOptional() @IsString() role?: string;
  @IsOptional() @IsString() primaryApp?: string;
  @IsOptional() @IsString() criticality?: string;
  @IsOptional() @IsString() assetOwnerId?: string;
  @IsOptional() @IsString() assetOwnerEmail?: string;
  @IsOptional() @IsString() appOwnerEmail?: string;
  @IsOptional() @IsBoolean() biaApp?: boolean;
}

export class UpdateInfrastructureAssetDto {
  @IsOptional() @IsString() serverName?: string;
  @IsOptional() @IsEnum(InfraType) type?: InfraType;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() hostname?: string;
  @IsOptional() @IsString() ip?: string;
  @IsOptional() @IsBoolean() publicIp?: boolean;
  @IsOptional() @IsString() location?: string;
  @IsOptional() @IsString() os?: string;
  @IsOptional() @IsString() role?: string;
  @IsOptional() @IsString() primaryApp?: string;
  @IsOptional() @IsString() criticality?: string;
  @IsOptional() @IsString() assetOwnerId?: string;
  @IsOptional() @IsString() assetOwnerEmail?: string;
  @IsOptional() @IsString() appOwnerEmail?: string;
  @IsOptional() @IsBoolean() biaApp?: boolean;
  @IsOptional() @IsBoolean() isActive?: boolean;
}

import { PaginationDto } from '../../common/dto/pagination.dto';

export class FilterInfrastructureAssetDto extends PaginationDto {
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() search?: string;
  @IsOptional() @IsString() serverId?: string;
  @IsOptional() @IsString() ip?: string;
  @IsOptional() @IsString() serverName?: string;
  @IsOptional() @IsString() type?: string;
  @IsOptional() @IsString() ownerName?: string;
  @IsOptional() @IsString() criticality?: string;
  @IsOptional() @IsString() startDate?: string;
  @IsOptional() @IsString() endDate?: string;
  @IsOptional() @IsString() sortBy?: string;
  @IsOptional() @IsString() sortDir?: string;
}
