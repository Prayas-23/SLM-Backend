import {
  IsEnum, IsNotEmpty, IsOptional, IsString, IsDateString,
} from 'class-validator';
import { CloudProvider, CloudResourceType, Environment } from '@prisma/client';

export class CreateCloudResourceDto {
  @IsString() @IsNotEmpty() resourceId: string;
  @IsString() @IsNotEmpty() resourceName: string;
  @IsEnum(CloudResourceType) type: CloudResourceType;
  @IsEnum(CloudProvider) cloudProvider: CloudProvider;
  @IsOptional() @IsString() resourceExtId?: string;
  @IsOptional() @IsString() technologyName?: string;
  @IsOptional() @IsString() stackLayer?: string;
  @IsOptional() @IsString() cloudAccountId?: string;
  @IsOptional() @IsString() status?: string;
  @IsOptional() @IsString() region?: string;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() infraAssetId?: string;
  @IsOptional() @IsDateString() firstSeen?: string;
}

export class UpdateCloudResourceDto {
  @IsOptional() @IsString() resourceName?: string;
  @IsOptional() @IsEnum(CloudResourceType) type?: CloudResourceType;
  @IsOptional() @IsEnum(CloudProvider) cloudProvider?: CloudProvider;
  @IsOptional() @IsString() resourceExtId?: string;
  @IsOptional() @IsString() technologyName?: string;
  @IsOptional() @IsString() stackLayer?: string;
  @IsOptional() @IsString() cloudAccountId?: string;
  @IsOptional() @IsString() status?: string;
  @IsOptional() @IsString() region?: string;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() infraAssetId?: string;
}

export class LinkAppCloudResourceDto {
  @IsString() @IsNotEmpty() applicationId: string;
}

import { PaginationDto } from '../../common/dto/pagination.dto';

export class FilterCloudResourceDto extends PaginationDto {
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() search?: string;
  @IsOptional() @IsString() resourceId?: string;
  @IsOptional() @IsString() resourceExtId?: string;
  @IsOptional() @IsString() resourceName?: string;
  @IsOptional() @IsString() type?: string;
  @IsOptional() @IsString() technologyName?: string;
  @IsOptional() @IsString() stackLayer?: string;
  @IsOptional() @IsString() cloudProvider?: string;
  @IsOptional() @IsString() cloudAccountId?: string;
  @IsOptional() @IsString() cloudAccountExtId?: string;
  @IsOptional() @IsString() cloudAccountProvider?: string;
  @IsOptional() @IsString() status?: string;
  @IsOptional() @IsString() region?: string;
  @IsOptional() @IsString() startDate?: string;
  @IsOptional() @IsString() endDate?: string;
  @IsOptional() @IsString() sortBy?: string;
  @IsOptional() @IsString() sortDir?: string;
}
