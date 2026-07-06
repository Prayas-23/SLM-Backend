import { IsEnum, IsOptional, IsString } from 'class-validator';
import { Environment, AssetType } from '@prisma/client';
import { PaginationDto } from '../../common/dto/pagination.dto';

export class FilterApplicationDto extends PaginationDto {
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() ownerId?: string;
  @IsOptional() @IsString() criticality?: string;
  @IsOptional() @IsString() search?: string;
  @IsOptional() @IsEnum(AssetType) type?: AssetType;
  @IsOptional() @IsString() department?: string;
  @IsOptional() @IsString() vaptStatus?: string;
  @IsOptional() @IsString() sortBy?: string;
  @IsOptional() @IsString() sortDir?: 'asc' | 'desc';
  @IsOptional() @IsString() appId?: string;
  @IsOptional() @IsString() name?: string;
  @IsOptional() @IsString() ownerName?: string;
}
