import { IsEnum, IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { CloudProvider, Environment } from '@prisma/client';

export class CreateCloudAccountDto {
  @IsString() @IsNotEmpty() accountId: string;
  @IsString() @IsNotEmpty() extId: string;
  @IsEnum(CloudProvider) provider: CloudProvider;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() label?: string;
}

export class UpdateCloudAccountDto {
  @IsOptional() @IsString() extId?: string;
  @IsOptional() @IsEnum(CloudProvider) provider?: CloudProvider;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() label?: string;
}

import { PaginationDto } from '../../common/dto/pagination.dto';

export class FilterCloudAccountDto extends PaginationDto {
  @IsOptional() @IsString() search?: string;
}
