import { Controller, Get, Post, Patch, Delete, Param, Body, Query, UseGuards } from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { InfrastructureAssetsService } from './infrastructure-assets.service';
import { CreateInfrastructureAssetDto, UpdateInfrastructureAssetDto, FilterInfrastructureAssetDto } from './dto/infrastructure-asset.dto';
import { PaginationDto } from '../common/dto/pagination.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('infrastructure-assets')
export class InfrastructureAssetsController {
  constructor(private readonly service: InfrastructureAssetsService) {}

  @Get()
  findAll(@Query() query: FilterInfrastructureAssetDto) {
    return this.service.findAll(query);
  }

  @Get('aggregate')
  aggregate(@Query() query: FilterInfrastructureAssetDto) {
    return this.service.aggregate(query);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  /** GET /infrastructure-assets/:id/scan-findings — CVS findings for an asset */
  @Get(':id/scan-findings')
  findScanFindings(@Param('id') id: string, @Query() query: PaginationDto) {
    return this.service.findScanFindings(id, query);
  }

  @Post()
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  create(@Body() dto: CreateInfrastructureAssetDto) {
    return this.service.create(dto);
  }

  @Patch(':id')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST, UserRole.INFRASTRUCTURE_OWNER)
  update(@Param('id') id: string, @Body() dto: UpdateInfrastructureAssetDto) {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  @Roles(UserRole.SECURITY_LEAD)
  remove(@Param('id') id: string) {
    return this.service.remove(id);
  }
}

