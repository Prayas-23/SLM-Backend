import { PrismaService } from '../../../prisma/prisma.service';
import { IntentFilters } from '../../dto/intent.dto';
import { Severity, CvsAssignmentMethod, Prisma } from '@prisma/client';

function buildCvsWhere(filters: IntentFilters): Prisma.ContinuousScanFindingWhereInput {
  const where: Prisma.ContinuousScanFindingWhereInput = {};

  if (filters.severity && Object.values(Severity).includes(filters.severity as Severity)) {
    where.severity = filters.severity as Severity;
  }
  if (filters.status) {
    where.status = filters.status.toUpperCase();
  }
  if (filters.asset) {
    where.assetName = { contains: filters.asset, mode: 'insensitive' };
  }
  if (filters.owner) {
    where.assignedOwnerName = { contains: filters.owner, mode: 'insensitive' };
  }
  // assignmentMethod is an intent filter we can optionally support
  if (filters.assignmentMethod && Object.values(CvsAssignmentMethod).includes(filters.assignmentMethod as CvsAssignmentMethod)) {
    where.assignmentMethod = filters.assignmentMethod as CvsAssignmentMethod;
  }

  return where;
}

const CVS_SELECT: Prisma.ContinuousScanFindingSelect = {
  id:               true,
  scannerName:      true,
  vulnTitle:        true,
  severity:         true,
  cvss:             true,
  cve:              true,
  status:           true,
  assetName:        true,
  assignedOwnerName: true,
  assignmentMethod: true,
  securityRequestId: true,
  vulnerabilityId:  true,
  firstSeenAt:      true,
  acceptedAt:       true,
};

export class ContinuousScanFindingHandler {
  constructor(private readonly prisma: PrismaService) {}

  async list(filters: IntentFilters, _rbacWhere: Record<string, unknown> | null, page = 1, limit = 20) {
    // CVS findings are global — accessible to all security roles
    const where = buildCvsWhere(filters);
    const [data, total] = await Promise.all([
      this.prisma.continuousScanFinding.findMany({
        where,
        select: CVS_SELECT,
        orderBy: [{ severity: 'asc' }, { firstSeenAt: 'desc' }],
        skip: (page - 1) * limit,
        take: limit,
      }),
      this.prisma.continuousScanFinding.count({ where }),
    ]);
    return { data, total };
  }

  async count(filters: IntentFilters, _rbacWhere: Record<string, unknown> | null) {
    const where = buildCvsWhere(filters);
    const [total, bySeverity, byStatus] = await Promise.all([
      this.prisma.continuousScanFinding.count({ where }),
      this.prisma.continuousScanFinding.groupBy({ by: ['severity'], where, _count: true }),
      this.prisma.continuousScanFinding.groupBy({ by: ['status'],   where, _count: true }),
    ]);
    return { data: [{ total, bySeverity, byStatus }], total: 1 };
  }

  async summary(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }

  async analyze(filters: IntentFilters, rbacWhere: Record<string, unknown> | null) {
    return this.count(filters, rbacWhere);
  }
}
