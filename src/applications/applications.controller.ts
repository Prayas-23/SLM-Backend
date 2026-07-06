import {
  Controller, Get, Post, Patch, Delete,
  Param, Body, Query, UseGuards, Req,
} from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { ApplicationsService } from './applications.service';
import { CreateApplicationDto } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { FilterApplicationDto } from './dto/filter-application.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('applications')
export class ApplicationsController {
  constructor(private readonly applicationsService: ApplicationsService) {}

  @Get()
  findAll(@Query() query: FilterApplicationDto) {
    return this.applicationsService.findAll(query);
  }

  @Get('aggregate')
  aggregate(@Query() query: FilterApplicationDto) {
    return this.applicationsService.aggregate(query);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.applicationsService.findOne(id);
  }

  @Post()
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  create(@Req() req: any, @Body() dto: CreateApplicationDto) {
    return this.applicationsService.create(dto, req.user);
  }

  @Patch(':id')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST, UserRole.APPLICATION_OWNER)
  update(@Req() req: any, @Param('id') id: string, @Body() dto: UpdateApplicationDto) {
    return this.applicationsService.update(id, dto, req.user);
  }

  @Delete(':id')
  @Roles(UserRole.SECURITY_LEAD)
  remove(@Req() req: any, @Param('id') id: string) {
    return this.applicationsService.remove(id, req.user);
  }
}
