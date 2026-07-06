import { PrismaService } from '../../../prisma/prisma.service';
import { IntentFilters } from '../../dto/intent.dto';
import { CloudProvider, Environment, Prisma } from '@prisma/client';

function buildCloudWhere(filters: IntentFilters): Prisma.CloudResourceWhereInput {
  const where: Prisma.CloudResourceWhereInput = { deletedAt: null };

  if (filters.environment && Object.values(Environment).includes(filters.environment as Environment)) {
    where.environment = filters.environment as Environment;
  }
  if (filters.asset) {
    where.resourceName = { contains: filters.asset, mode: 'insensitive' };
  }

  return where;
}

const CLOUD_SELECT: Prisma.CloudResourceSelect = {
  id:             true,
  resourceId:     true,
  resourceName:   true,
  type:           true,
  cloudProvider:  true,
  technologyName: true,
  stackLayer:     true,
  status:         true,
  region:         true,
  environment:    true,
  firstSeen:      true,
  cloudAccount:   { select: { accountId: true, extId: true, label: true } },
};

export class CloudResourceHandler {
  constructor(private readonly prisma: PrismaService) {}

  async list(filters: IntentFilters, _rbacWhere: Record<string, unknown> | null, page = 1, limit = 20) {
    const where = buildCloudWhere(filters);
    const [data, total] = await Promise.all([
      this.prisma.cloudResource.findMany({ where, select: CLOUD_SELECT, orderBy: { resourceName: 'asc' }, skip: (page - 1) * limit, take: limit }),
      this.prisma.cloudResource.count({ where }),
    ]);
    return { data, total };
  }

  async count(filters: IntentFilters, _rbacWhere: Record<string, unknown> | null) {
    const where = buildCloudWhere(filters);
    const [total, byProvider, byType, byEnv] = await Promise.all([
      this.prisma.cloudResource.count({ where }),
      this.prisma.cloudResource.groupBy({ by: ['cloudProvider'], where, _count: true }),
      this.prisma.cloudResource.groupBy({ by: ['type'],          where, _count: true }),
      this.prisma.cloudResource.groupBy({ by: ['environment'],   where, _count: true }),
    ]);
    return { data: [{ total, byProvider, byType, byEnv }], total: 1 };
  }

  async summary(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }

  async analyze(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }
}
