import { PrismaService } from '../../../prisma/prisma.service';
import { IntentFilters } from '../../dto/intent.dto';
import {
  RequestSource,
  RequestStatus,
  Environment,
  Prisma,
} from '@prisma/client';

function buildSecurityRequestWhere(
  filters: IntentFilters,
  rbacWhere: Record<string, unknown> | null,
): Prisma.SecurityRequestWhereInput {
  const where: Prisma.SecurityRequestWhereInput = { deletedAt: null };

  if (filters.source && Object.values(RequestSource).includes(filters.source as RequestSource)) {
    where.source = filters.source as RequestSource;
  }
  if (filters.status && Object.values(RequestStatus).includes(filters.status as RequestStatus)) {
    where.status = filters.status as RequestStatus;
  }
  if (filters.environment && Object.values(Environment).includes(filters.environment as Environment)) {
    where.environment = filters.environment as Environment;
  }
  if (filters.requestId) {
    where.reqId = filters.requestId;
  }
  if (filters.application) {
    where.targetApp = { name: { contains: filters.application, mode: 'insensitive' } };
  }
  if (filters.assignee) {
    where.assignedTo = { name: { contains: filters.assignee, mode: 'insensitive' } };
  }
  if (rbacWhere) Object.assign(where, rbacWhere);

  return where;
}

const SR_SELECT: Prisma.SecurityRequestSelect = {
  id:          true,
  reqId:       true,
  source:      true,
  environment: true,
  status:      true,
  partner:     true,
  initiatedOn: true,
  targetApp:   { select: { name: true, appId: true } },
  targetInfra: { select: { serverName: true, serverId: true } },
  assignedTo:  { select: { name: true } },
  _count:      { select: { vulnerabilities: true } },
};

export class SecurityRequestHandler {
  constructor(private readonly prisma: PrismaService) {}

  async list(filters: IntentFilters, rbacWhere: Record<string, unknown> | null, page = 1, limit = 20) {
    const where = buildSecurityRequestWhere(filters, rbacWhere);
    const [data, total] = await Promise.all([
      this.prisma.securityRequest.findMany({
        where,
        select: SR_SELECT,
        orderBy: { initiatedOn: 'desc' },
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.securityRequest.count({ where }),
    ]);
    return { data, total };
  }

  async count(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    const where = buildSecurityRequestWhere(filters, rbacWhere);
    const [total, bySource, byStatus] = await Promise.all([
      this.prisma.securityRequest.count({ where }),
      this.prisma.securityRequest.groupBy({ by: ['source'], where, _count: true }),
      this.prisma.securityRequest.groupBy({ by: ['status'], where, _count: true }),
    ]);
    return { data: [{ total, bySource, byStatus }], total: 1 };
  }

  async summary(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }

  async analyze(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }
}
