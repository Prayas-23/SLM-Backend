import { Module } from '@nestjs/common';
import { DashboardController } from './dashboard.controller';
import { DashboardService } from './dashboard.service';
import { SlaModule } from '../sla/sla.module';

/**
 * Dashboard Module – Phase 2G
 *
 * Provides read-only aggregation endpoints for the Sentinel SLM frontend.
 * Imports SlaModule to reuse SlaMetricsService (Phase 2F).
 * Depends on PrismaModule (global) for all other queries.
 *
 * Endpoints:
 *   GET /dashboard/overview
 *   GET /dashboard/vulnerabilities
 *   GET /dashboard/security-requests
 *   GET /dashboard/sla
 *   GET /dashboard/applications
 *   GET /dashboard/infrastructure
 *   GET /dashboard/cloud
 */
@Module({
  imports: [SlaModule],
  controllers: [DashboardController],
  providers: [DashboardService],
})
export class DashboardModule {}
