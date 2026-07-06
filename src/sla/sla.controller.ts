import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { UserRole, Environment } from '@prisma/client';
import { SlaMetricsService } from './sla-metrics.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { IsOptional, IsEnum, IsDateString, IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';

class SlaFilterDto {
  @IsOptional() @IsEnum(Environment)
  environment?: Environment;

  @IsOptional() @IsDateString()
  startDate?: string;

  @IsOptional() @IsDateString()
  endDate?: string;
}

class SlaBreachFilterDto extends SlaFilterDto {
  @IsOptional() @Type(() => Number) @IsInt() @Min(1)
  page?: number;

  @IsOptional() @Type(() => Number) @IsInt() @Min(1)
  limit?: number;
}

const SLA_ROLES = [
  UserRole.SECURITY_LEAD,
  UserRole.SECURITY_ANALYST,
  UserRole.READ_ONLY,
];

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('sla')
export class SlaController {
  constructor(private readonly metrics: SlaMetricsService) {}

  /**
   * GET /sla/summary
   * High-level KPIs: total, withinSla, breached, critBreached, highBreached, compliancePct
   */
  @Get('summary')
  @Roles(...SLA_ROLES)
  getSummary(@Query() filter: SlaFilterDto) {
    return this.metrics.getSummary(filter);
  }

  /**
   * GET /sla/compliance
   * Overall compliance percentage with total/compliant/breached counts
   */
  @Get('compliance')
  @Roles(...SLA_ROLES)
  getCompliance(@Query() filter: SlaFilterDto) {
    return this.metrics.getCompliance(filter);
  }

  /**
   * GET /sla/breaches
   * Paginated list of currently breached vulnerabilities
   */
  @Get('breaches')
  @Roles(...SLA_ROLES)
  getBreaches(@Query() filter: SlaBreachFilterDto) {
    return this.metrics.getBreaches(filter);
  }

  /**
   * GET /sla/by-severity
   * Compliance breakdown per severity level
   */
  @Get('by-severity')
  @Roles(...SLA_ROLES)
  getBySeverity(@Query() filter: SlaFilterDto) {
    return this.metrics.getBySeverity(filter);
  }

  /**
   * GET /sla/by-environment
   * Compliance breakdown per environment
   */
  @Get('by-environment')
  @Roles(...SLA_ROLES)
  getByEnvironment(@Query() filter: SlaFilterDto) {
    return this.metrics.getByEnvironment(filter);
  }

  /**
   * GET /sla/trend
   * Daily breach counts for the last 30 days (dashboard chart data)
   */
  @Get('trend')
  @Roles(...SLA_ROLES)
  getBreachTrend(@Query() filter: SlaFilterDto) {
    return this.metrics.getBreachTrend(filter);
  }
}
