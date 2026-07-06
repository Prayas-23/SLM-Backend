import { Controller, Get, Post, Patch, Delete, Param, Body, Query, UseGuards } from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { CloudAccountsService } from './cloud-accounts.service';
import { CreateCloudAccountDto, UpdateCloudAccountDto, FilterCloudAccountDto } from './dto/cloud-account.dto';
import { PaginationDto } from '../common/dto/pagination.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('cloud-accounts')
export class CloudAccountsController {
  constructor(private readonly service: CloudAccountsService) {}

  @Get()
  findAll(@Query() query: FilterCloudAccountDto) {
    return this.service.findAll(query);
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  @Post()
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  create(@Body() dto: CreateCloudAccountDto) {
    return this.service.create(dto);
  }

  @Patch(':id')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  update(@Param('id') id: string, @Body() dto: UpdateCloudAccountDto) {
    return this.service.update(id, dto);
  }

  @Delete(':id')
  @Roles(UserRole.SECURITY_LEAD)
  remove(@Param('id') id: string) {
    return this.service.remove(id);
  }
}
