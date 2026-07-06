import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const reqs = await prisma.securityRequest.findMany({
    include: {
      assignedTo: true,
      targetApp: true,
      targetInfra: true
    }
  });

  const stats = {
    OPEN: { roles: {} as Record<string, number>, total: 0, violations: [] as string[] },
    SUBMITTED: { roles: {} as Record<string, number>, total: 0, violations: [] as string[] },
    IN_PROGRESS: { roles: {} as Record<string, number>, total: 0, violations: [] as string[] },
    PATCHING: { roles: {} as Record<string, number>, total: 0, violations: [] as string[] },
    REVALIDATION: { roles: {} as Record<string, number>, total: 0, violations: [] as string[] },
    CLOSED: { roles: {} as Record<string, number>, total: 0, violations: [] as string[] },
  };

  for (const req of reqs) {
    const status = req.status as string;
    const role = req.assignedTo?.role ?? 'UNASSIGNED';
    
    if (!stats[status]) continue;

    stats[status].total++;
    stats[status].roles[role] = (stats[status].roles[role] || 0) + 1;

    let expectedOwner = 'UNKNOWN';
    if (status === 'OPEN' || status === 'SUBMITTED') expectedOwner = 'SECURITY_ANALYST or SECURITY_LEAD';
    if (status === 'IN_PROGRESS' || status === 'REVALIDATION') expectedOwner = 'SECURITY_ANALYST';
    if (status === 'PATCHING') expectedOwner = 'APPLICATION_OWNER or INFRASTRUCTURE_OWNER';
    if (status === 'CLOSED') expectedOwner = 'APPLICATION_OWNER or INFRASTRUCTURE_OWNER or SECURITY_ANALYST';

    let isValid = false;
    if (status === 'OPEN' || status === 'SUBMITTED') isValid = (role === 'SECURITY_ANALYST' || role === 'SECURITY_LEAD');
    else if (status === 'IN_PROGRESS' || status === 'REVALIDATION') isValid = role === 'SECURITY_ANALYST';
    else if (status === 'PATCHING') isValid = (role === 'APPLICATION_OWNER' || role === 'INFRASTRUCTURE_OWNER');
    else if (status === 'CLOSED') isValid = (role === 'APPLICATION_OWNER' || role === 'INFRASTRUCTURE_OWNER' || role === 'SECURITY_ANALYST');

    if (!isValid) {
      stats[status].violations.push(`${req.reqId} is ${status} but assigned to ${role}. Expected: ${expectedOwner}`);
    }
  }

  console.log(JSON.stringify(stats, null, 2));
}

main().catch(console.error).finally(() => prisma.$disconnect());
