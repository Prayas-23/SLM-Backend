import { Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Environment, Severity, VulnerabilityStatus } from '@prisma/client';

export interface SlaFilter {
  environment?: Environment;
  startDate?: string;
  endDate?: string;
}

@Injectable()
export class SlaMetricsService {
  constructor(private readonly prisma: PrismaService) {}

  // ── Shared where clause ───────────────────────────────────────────────────

  private buildWhere(filter: SlaFilter) {
    const where: Record<string, unknown> = {
      deletedAt: null,
      status: { not: VulnerabilityStatus.CLOSED },
    };
    if (filter.environment) where.environment = filter.environment;
    if (filter.startDate || filter.endDate) {
      where.createdAt = {
        ...(filter.startDate && { gte: new Date(filter.startDate) }),
        ...(filter.endDate && { lte: new Date(filter.endDate) }),
      };
    }
    return where;
  }

  // ── Summary ───────────────────────────────────────────────────────────────

  async getSummary(filter: SlaFilter) {
    const where = this.buildWhere(filter);
    const now = new Date();

    const [total, withinSla, breached, critBreached, highBreached] =
      await this.prisma.$transaction([
        this.prisma.vulnerability.count({ where }),
        this.prisma.vulnerability.count({
          where: { ...where, slaDueDate: { gt: now } },
        }),
        this.prisma.vulnerability.count({
          where: {
            ...where,
            slaTracking: { isBreached: true },
          },
        }),
        this.prisma.vulnerability.count({
          where: {
            ...where,
            severity: Severity.CRITICAL,
            slaTracking: { isBreached: true },
          },
        }),
        this.prisma.vulnerability.count({
          where: {
            ...where,
            severity: Severity.HIGH,
            slaTracking: { isBreached: true },
          },
        }),
      ]);

    const compliancePct = total > 0 ? Math.round((withinSla / total) * 100) : 100;

    return {
      total,
      withinSla,
      breached,
      critBreached,
      highBreached,
      compliancePct,
    };
  }

  // ── Compliance ────────────────────────────────────────────────────────────

  async getCompliance(filter: SlaFilter) {
    const where = this.buildWhere(filter);
    const now = new Date();

    const [total, compliant] = await this.prisma.$transaction([
      this.prisma.vulnerability.count({ where }),
      this.prisma.vulnerability.count({
        where: { ...where, slaDueDate: { gt: now } },
      }),
    ]);

    const breached = total - compliant;
    const pct = total > 0 ? Math.round((compliant / total) * 100) : 100;

    return { total, compliant, breached, compliancePct: pct };
  }

  // ── Breaches ──────────────────────────────────────────────────────────────

  async getBreaches(filter: SlaFilter & { page?: number; limit?: number }) {
    const where = {
      ...this.buildWhere(filter),
      slaTracking: { isBreached: true },
    };
    const page = filter.page ?? 1;
    const limit = filter.limit ?? 20;
    const skip = (page - 1) * limit;

    const [data, total] = await this.prisma.$transaction([
      this.prisma.vulnerability.findMany({
        where,
        select: {
          id: true, vulnId: true, shortDesc: true, severity: true,
          status: true, environment: true, slaDueDate: true,
          assignedTo: { select: { id: true, name: true, email: true } },
          slaTracking: { select: { dueDate: true, breachedAt: true, daysRemaining: true } },
          request: { select: { reqId: true, source: true } },
        },
        orderBy: { slaDueDate: 'asc' },
        skip,
        take: limit,
      }),
      this.prisma.vulnerability.count({ where }),
    ]);

    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  // ── By Severity ───────────────────────────────────────────────────────────

  async getBySeverity(filter: SlaFilter) {
    const where = this.buildWhere(filter);
    const now = new Date();

    const severities = Object.values(Severity);
    const rows = await Promise.all(
      severities.map(async (severity) => {
        const sevWhere = { ...where, severity };
        const [total, compliant, breached] = await this.prisma.$transaction([
          this.prisma.vulnerability.count({ where: sevWhere }),
          this.prisma.vulnerability.count({ where: { ...sevWhere, slaDueDate: { gt: now } } }),
          this.prisma.vulnerability.count({ where: { ...sevWhere, slaTracking: { isBreached: true } } }),
        ]);
        const pct = total > 0 ? Math.round((compliant / total) * 100) : 100;
        return { severity, total, compliant, breached, compliancePct: pct };
      }),
    );

    return rows;
  }

  // ── By Environment ────────────────────────────────────────────────────────

  async getByEnvironment(filter: Omit<SlaFilter, 'environment'>) {
    const environments = Object.values(Environment);
    const now = new Date();

    const rows = await Promise.all(
      environments.map(async (environment) => {
        const baseWhere = this.buildWhere({ ...filter, environment });
        const [total, compliant, breached] = await this.prisma.$transaction([
          this.prisma.vulnerability.count({ where: baseWhere }),
          this.prisma.vulnerability.count({ where: { ...baseWhere, slaDueDate: { gt: now } } }),
          this.prisma.vulnerability.count({ where: { ...baseWhere, slaTracking: { isBreached: true } } }),
        ]);
        const pct = total > 0 ? Math.round((compliant / total) * 100) : 100;
        return { environment, total, compliant, breached, compliancePct: pct };
      }),
    );

    return rows;
  }

  // ── Breach Trend (last 30 days, daily buckets) ────────────────────────────

  async getBreachTrend(filter: SlaFilter) {
    const days = 30;
    const now = new Date();
    const trend: { date: string; breached: number }[] = [];

    for (let i = days - 1; i >= 0; i--) {
      const day = new Date(now);
      day.setDate(day.getDate() - i);
      const dayStart = new Date(day.getFullYear(), day.getMonth(), day.getDate());
      const dayEnd = new Date(dayStart);
      dayEnd.setDate(dayEnd.getDate() + 1);

      const where: Record<string, unknown> = {
        deletedAt: null,
        slaTracking: {
          isBreached: true,
          breachedAt: { gte: dayStart, lt: dayEnd },
        },
      };
      if (filter.environment) where.environment = filter.environment;

      const count = await this.prisma.vulnerability.count({ where });
      trend.push({ date: dayStart.toISOString().split('T')[0], breached: count });
    }

    return trend;
  }
}
