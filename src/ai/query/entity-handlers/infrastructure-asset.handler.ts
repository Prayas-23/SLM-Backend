import { PrismaService } from '../../../prisma/prisma.service';
import { IntentFilters } from '../../dto/intent.dto';
import { Environment, Prisma } from '@prisma/client';

function buildInfraWhere(filters: IntentFilters, rbacWhere: Record<string, unknown> | null): Prisma.InfrastructureAssetWhereInput {
  const where: Prisma.InfrastructureAssetWhereInput = { deletedAt: null, isActive: true };
  if (filters.environment && Object.values(Environment).includes(filters.environment as Environment)) {
    where.environment = filters.environment as Environment;
  }
  if (filters.asset) {
    where.serverName = { contains: filters.asset, mode: 'insensitive' };
  }
  if (filters.owner) {
    where.assetOwner = { name: { contains: filters.owner, mode: 'insensitive' } };
  }
  if (rbacWhere) Object.assign(where, rbacWhere);
  return where;
}

const INFRA_SELECT: Prisma.InfrastructureAssetSelect = {
  id:          true,
  serverId:    true,
  serverName:  true,
  hostname:    true,
  ip:          true,
  type:        true,
  environment: true,
  location:    true,
  os:          true,
  criticality: true,
  assetOwner:  { select: { name: true, email: true } },
  _count:      { select: { securityRequests: true, scanFindings: true } },
};

export class InfrastructureAssetHandler {
  constructor(private readonly prisma: PrismaService) {}

  async list(filters: IntentFilters, rbacWhere: Record<string, unknown> | null, page = 1, limit = 20) {
    const where = buildInfraWhere(filters, rbacWhere);
    const [data, total] = await Promise.all([
      this.prisma.infrastructureAsset.findMany({ where, select: INFRA_SELECT, orderBy: { serverName: 'asc' }, skip: (page - 1) * limit, take: limit }),
      this.prisma.infrastructureAsset.count({ where }),
    ]);
    return { data, total };
  }

  async count(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    const where = buildInfraWhere(filters, rbacWhere);
    const [total, byEnv, byType] = await Promise.all([
      this.prisma.infrastructureAsset.count({ where }),
      this.prisma.infrastructureAsset.groupBy({ by: ['environment'], where, _count: true }),
      this.prisma.infrastructureAsset.groupBy({ by: ['type'], where, _count: true }),
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
