import {
  Controller, Get, Post, Param, Body, Query, Request, UseGuards,
} from '@nestjs/common';
import { ContinuousScanService } from './continuous-scan.service';
import {
  FilterCvsFindingDto,
  CreateCvsFindingDto,
  AssignByAssetDto,
  AcceptFindingDto,
} from './dto/continuous-scan.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '@prisma/client';

const READ_ROLES = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
  UserRole.APPLICATION_OWNER,
  UserRole.INFRASTRUCTURE_OWNER,
  UserRole.READ_ONLY,
];

const ANALYST_ROLES = [UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST];

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('continuous-scan')
export class ContinuousScanController {
  constructor(private readonly svc: ContinuousScanService) {}

  // ── List Findings ──────────────────────────────────────────────────────────

  /** GET /continuous-scan — list all findings with optional filters */
  @Get()
  @Roles(...READ_ROLES)
  findAll(@Query() filter: FilterCvsFindingDto) {
    return this.svc.findAll(filter);
  }

  /** GET /continuous-scan/:id — get a single CVS finding */
  @Get(':id')
  @Roles(...READ_ROLES)
  findOne(@Param('id') id: string) {
    return this.svc.findOne(id);
  }

  // ── Create (Manual Entry) ──────────────────────────────────────────────────

  /** POST /continuous-scan — create a manual CVS finding */
  @Post()
  @Roles(...ANALYST_ROLES)
  create(@Body() dto: CreateCvsFindingDto, @Request() req: any) {
    return this.svc.createManual(dto, { id: req.user.id, name: req.user.name });
  }

  // ── Assignment ────────────────────────────────────────────────────────────

  /**
   * POST /continuous-scan/:id/auto-assign
   * Auto-assigns a single finding to the Infrastructure Asset owner.
   */
  @Post(':id/auto-assign')
  @Roles(...ANALYST_ROLES)
  autoAssign(@Param('id') id: string, @Request() req: any) {
    return this.svc.autoAssign(id, { id: req.user.id, name: req.user.name });
  }

  /**
   * POST /continuous-scan/assign-by-asset
   * Assigns all (or selected) unassigned findings for an asset to its owner.
   */
  @Post('assign-by-asset')
  @Roles(...ANALYST_ROLES)
  assignByAsset(@Body() dto: AssignByAssetDto, @Request() req: any) {
    return this.svc.assignByAsset(dto, { id: req.user.id, name: req.user.name });
  }

  /**
   * POST /continuous-scan/assign-all
   * Bulk-assigns every NEW finding to the respective asset owner.
   */
  @Post('assign-all')
  @Roles(...ANALYST_ROLES)
  assignAll(@Request() req: any) {
    return this.svc.assignAll({ id: req.user.id, name: req.user.name });
  }

  // ── Accept ────────────────────────────────────────────────────────────────

  /**
   * POST /continuous-scan/:id/accept
   * Accepts a CVS finding: atomically creates SecurityRequest + Vulnerability.
   */
  @Post(':id/accept')
  @Roles(...ANALYST_ROLES)
  accept(@Param('id') id: string, @Body() dto: AcceptFindingDto, @Request() req: any) {
    return this.svc.acceptFinding(id, dto, {
      id: req.user.id,
      name: req.user.name,
      role: req.user.role,
    });
  }

  // ── Legacy: Mark Patched — REMOVED ──────────────────────────────────────────
  // PATCHED is not a valid ContinuousScanFinding status.
  // Remediation is tracked on the linked Vulnerability, not the finding.
  // Endpoint PATCH /continuous-scan/:id/patch has been removed.
}
