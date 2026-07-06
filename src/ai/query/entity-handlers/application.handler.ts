import { PrismaService } from '../../../prisma/prisma.service';
import { IntentFilters } from '../../dto/intent.dto';
import { Environment, Prisma } from '@prisma/client';

function buildAppWhere(filters: IntentFilters, rbacWhere: Record<string, unknown> | null): Prisma.ApplicationWhereInput {
  const where: Prisma.ApplicationWhereInput = { deletedAt: null, isActive: true };
  if (filters.environment && Object.values(Environment).includes(filters.environment as Environment)) {
    where.environment = filters.environment as Environment;
  }
  if (filters.application) {
    where.name = { contains: filters.application, mode: 'insensitive' };
  }
  if (filters.owner) {
    where.owner = { name: { contains: filters.owner, mode: 'insensitive' } };
  }
  if (rbacWhere) Object.assign(where, rbacWhere);
  return where;
}

const APP_SELECT: Prisma.ApplicationSelect = {
  id:            true,
  appId:         true,
  name:          true,
  type:          true,
  environment:   true,
  criticality:   true,
  classification: true,
  vaptStatus:    true,
  lastVaptDate:  true,
  nextVaptDate:  true,
  owner:         { select: { name: true, email: true } },
  _count:        { select: { securityRequests: true } },
};

export class ApplicationHandler {
  constructor(private readonly prisma: PrismaService) {}

  async list(filters: IntentFilters, rbacWhere: Record<string, unknown> | null, page = 1, limit = 20) {
    const where = buildAppWhere(filters, rbacWhere);
    const [data, total] = await Promise.all([
      this.prisma.application.findMany({ where, select: APP_SELECT, orderBy: { name: 'asc' }, skip: (page - 1) * limit, take: limit }),
      this.prisma.application.count({ where }),
    ]);
    return { data, total };
  }

  async count(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    const where = buildAppWhere(filters, rbacWhere);
    const [total, byEnv, byType] = await Promise.all([
      this.prisma.application.count({ where }),
      this.prisma.application.groupBy({ by: ['environment'], where, _count: true }),
      this.prisma.application.groupBy({ by: ['type'], where, _count: true }),
    ]);
    return { data: [{ total, byEnv, byType }], total: 1 };
  }

  async summary(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }

  async analyze(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }
}
