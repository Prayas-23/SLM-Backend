import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Param,
  Query,
  Body,
  Req,
  Res,
  UseGuards,
  ParseUUIDPipe,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { Response, Request } from 'express';
import { UserRole } from '@prisma/client';
import { ReportsService } from './reports.service';
import {
  GenerateReportDto,
  ScheduleReportDto,
  UpdateScheduleDto,
  ListReportsDto,
} from './dto/report.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

// ── Roles that can access Reports ─────────────────────────────────────────────
const ALL_ROLES = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
  UserRole.APPLICATION_OWNER,
  UserRole.INFRASTRUCTURE_OWNER,
  UserRole.READ_ONLY,
];

// Only SECURITY_LEAD and SECURITY_ANALYST can generate / schedule reports
const GENERATE_ROLES = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
];

// Only SECURITY_LEAD can delete schedules
const ADMIN_ROLES = [UserRole.SECURITY_LEAD];

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('reports')
export class ReportsController {
  constructor(private readonly reportsService: ReportsService) {}

  // ── List reports ────────────────────────────────────────────────────────────

  /**
   * GET /reports
   * Returns reports belonging to the authenticated user.
   * Supports ?status=READY&startDate=...&endDate=...
   */
  @Get()
  @Roles(...ALL_ROLES)
  findAll(@Query() filter: ListReportsDto, @Req() req: Request) {
    const actor = req.user as { id: string };
    return this.reportsService.findAll(filter, actor.id);
  }

  // ── Get single report ───────────────────────────────────────────────────────

  /**
   * GET /reports/:id
   */
  @Get(':id')
  @Roles(...ALL_ROLES)
  findOne(@Param('id', ParseUUIDPipe) id: string) {
    return this.reportsService.findOne(id);
  }

  // ── Generate report ─────────────────────────────────────────────────────────

  /**
   * POST /reports/generate
   *
   * Creates a PENDING Report record and enqueues async generation via BullMQ.
   * Returns the Report object immediately with status=PENDING.
   * Poll GET /reports/:id until status=READY, then call GET /reports/download/:id.
   *
   * Body:
   *   {
   *     "title": "Q2 Vulnerability Report",
   *     "type": "VULNERABILITIES",
   *     "format": "XLSX",
   *     "environment": "PRODUCTION",   // optional
   *     "startDate": "2026-01-01",      // optional
   *     "endDate": "2026-06-30"         // optional
   *   }
   */
  @Post('generate')
  @Roles(...GENERATE_ROLES)
  @HttpCode(HttpStatus.ACCEPTED)
  generate(@Body() dto: GenerateReportDto, @Req() req: Request) {
    const actor = req.user as { id: string; name: string };
    return this.reportsService.generate(dto, actor);
  }

  // ── Download report ─────────────────────────────────────────────────────────

  /**
   * GET /reports/download/:id
   *
   * Streams the generated file as a download.
   * Returns 400 if the report is not READY or has expired.
   */
  @Get('download/:id')
  @Roles(...ALL_ROLES)
  async download(
    @Param('id', ParseUUIDPipe) id: string,
    @Res() res: Response,
  ) {
    const { stream, filename, mime } = await this.reportsService.getDownloadStream(id);
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', mime);
    stream.pipe(res);
  }

  // ── Schedule management ─────────────────────────────────────────────────────

  /**
   * POST /reports/schedule
   *
   * Creates a recurring report schedule.
   *
   * Body:
   *   {
   *     "title": "Weekly SLA Report",
   *     "type": "SLA",
   *     "format": "CSV",
   *     "cronExpr": "0 8 * * 1",
   *     "recipients": ["user@example.com"],
   *     "environment": "PRODUCTION"
   *   }
   */
  @Post('schedule')
  @Roles(...GENERATE_ROLES)
  createSchedule(@Body() dto: ScheduleReportDto, @Req() req: Request) {
    const actor = req.user as { id: string; name: string };
    return this.reportsService.createSchedule(dto, actor);
  }

  /**
   * PATCH /reports/schedule/:id
   *
   * Updates an existing report schedule.
   */
  @Patch('schedule/:id')
  @Roles(...GENERATE_ROLES)
  updateSchedule(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateScheduleDto,
    @Req() req: Request,
  ) {
    const actor = req.user as { id: string; name: string };
    return this.reportsService.updateSchedule(id, dto, actor);
  }

  /**
   * DELETE /reports/schedule/:id
   *
   * Deletes a report schedule permanently.
   * Restricted to SECURITY_LEAD.
   */
  @Delete('schedule/:id')
  @Roles(...ADMIN_ROLES)
  @HttpCode(HttpStatus.OK)
  deleteSchedule(
    @Param('id', ParseUUIDPipe) id: string,
    @Req() req: Request,
  ) {
    const actor = req.user as { id: string; name: string };
    return this.reportsService.deleteSchedule(id, actor);
  }
}
