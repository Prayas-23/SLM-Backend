import { Controller, Get, Post, Body, Patch, Param, Query, UseGuards } from '@nestjs/common';
import { FindingsService } from './findings.service';
import { CreateFindingDto, FilterFindingDto, UpdateFindingStatusDto } from './dto/finding.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '@prisma/client';

@Controller('findings')
@UseGuards(JwtAuthGuard, RolesGuard)
export class FindingsController {
  constructor(private readonly findingsService: FindingsService) {}

  @Post()
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  create(@Body() createFindingDto: CreateFindingDto) {
    return this.findingsService.create(createFindingDto);
  }

  @Get()
  findAll(@Query() query: FilterFindingDto) {
    return this.findingsService.findAll(query);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.findingsService.findOne(id);
  }

  @Patch(':id/status')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  updateStatus(@Param('id') id: string, @Body() updateStatusDto: UpdateFindingStatusDto) {
    return this.findingsService.updateStatus(id, updateStatusDto);
  }

  @Post(':id/convert')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  convertToVulnerability(@Param('id') id: string) {
    return this.findingsService.convertToVulnerability(id);
  }
}
