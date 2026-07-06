import {
  IsBoolean, IsEnum, IsOptional, IsString, IsDateString,
} from 'class-validator';
import { AssetType, Environment } from '@prisma/client';

export class UpdateApplicationDto {
  @IsOptional() @IsString() name?: string;
  @IsOptional() @IsString() description?: string;
  @IsOptional() @IsEnum(AssetType) type?: AssetType;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsString() department?: string;
  @IsOptional() @IsString() classification?: string;
  @IsOptional() @IsString() criticality?: string;
  @IsOptional() @IsString() ownerId?: string;
  @IsOptional() @IsString() ownerEmail?: string;
  @IsOptional() @IsBoolean() internetAccessible?: boolean;
  @IsOptional() @IsBoolean() piiData?: boolean;
  @IsOptional() @IsBoolean() biaApp?: boolean;
  @IsOptional() @IsString() prodUrl?: string;
  @IsOptional() @IsString() preprodUrl?: string;
  @IsOptional() @IsString() devUrl?: string;
  @IsOptional() @IsString() vaptStatus?: string;
  @IsOptional() @IsDateString() lastVaptDate?: string;
  @IsOptional() @IsDateString() nextVaptDate?: string;
  @IsOptional() @IsBoolean() isActive?: boolean;
}
