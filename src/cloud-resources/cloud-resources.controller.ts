import {
  Controller, Get, Post, Patch, Delete,
  Param, Body, Query, UseGuards,
} from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { CloudResourcesService } from './cloud-resources.service';
import {
  CreateCloudResourceDto,
  UpdateCloudResourceDto,
  LinkAppCloudResourceDto,
  FilterCloudResourceDto,
} from './dto/cloud-resource.dto';
import { PaginationDto } from '../common/dto/pagination.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('cloud-resources')
export class CloudResourcesController {
  constructor(private readonly service: CloudResourcesService) {}

  @Get()
  findAll(@Query() query: FilterCloudResourceDto) {
    return this.service.findAll(query);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  @Post()
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  create(@Body() dto: CreateCloudResourceDto) {
    return this.service.create(dto);
  }

  @Patch(':id')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  update(@Param('id') id: string, @Body() dto: UpdateCloudResourceDto) {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  @Roles(UserRole.SECURITY_LEAD)
  remove(@Param('id') id: string) {
    return this.service.remove(id);
  }

  // ── M2M: Application ↔ CloudResource ─────────────────────────────────────

  /** POST /cloud-resources/:id/applications — link an application */
  @Post(':id/applications')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  linkApplication(
    @Param('id') id: string,
    @Body() dto: LinkAppCloudResourceDto,
  ) {
    return this.service.linkApplication(id, dto);
  }

  /** DELETE /cloud-resources/:id/applications/:appId — unlink */
  @Delete(':id/applications/:appId')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  unlinkApplication(
    @Param('id') id: string,
    @Param('appId') appId: string,
  ) {
    return this.service.unlinkApplication(id, appId);
  }
}
