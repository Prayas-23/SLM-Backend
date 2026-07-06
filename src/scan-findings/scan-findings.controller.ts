import {
  Controller, Get, Post, Param, Query, UseGuards, Request,
} from '@nestjs/common';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { ScanFindingsService, FilterScanFindingDto } from './scan-findings.service';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('scan-findings')
export class ScanFindingsController {
  constructor(private readonly service: ScanFindingsService) {}

  /** GET /scan-findings — list all scan findings with optional filters */
  @Get()
  findAll(@Query() query: FilterScanFindingDto) {
    return this.service.findAll(query);
  }

  /** GET /scan-findings/:id — single finding detail */
  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  /** POST /scan-findings/:id/create-va — promote finding to VA security request */
  @Post(':id/create-va')
  createVaRequest(@Param('id') id: string, @Request() req: any) {
    return this.service.createVaRequest(id, { id: req.user.id, name: req.user.name });
  }
}
