import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function runAudit() {
  const allVulns = await prisma.vulnerability.findMany({
    include: {
      request: {
        include: { targetApp: true, targetInfra: true }
      },
      assignedTo: true,
      slaTracking: true,
    }
  });

  const allRequests = await prisma.securityRequest.findMany();

  // 1. Overall stats
  const totalVulns = allVulns.length;
  const closedStatus = ['CLOSED'];
  const closedVulns = allVulns.filter(v => closedStatus.includes(v.status)).length;
  const openVulns = totalVulns - closedVulns;

  const countByStatus: Record<string, number> = {};
  const countBySeverity: Record<string, number> = {};
  const countBySource: Record<string, number> = {};
  const countByApp: Record<string, number> = {};
  const countByEnv: Record<string, number> = {};
  const countByBU: Record<string, number> = {};

  // Sources stats
  const sourceStats: Record<string, { total: number, severities: Record<string, number>, statuses: Record<string, number> }> = {};

  // Timeline
  let minDate = new Date().getTime();
  let maxDate = 0;
  let sameDayCreatedClosed = 0;

  // Assignments
  const assignments: Record<string, number> = {};
  let unassigned = 0;

  // SLA
  let withinSla = 0;
  let breachedSla = 0;

  allVulns.forEach(v => {
    // Status
    countByStatus[v.status] = (countByStatus[v.status] || 0) + 1;
    // Severity
    countBySeverity[v.severity] = (countBySeverity[v.severity] || 0) + 1;
    // Source
    const src = v.source || 'UNKNOWN';
    countBySource[src] = (countBySource[src] || 0) + 1;
    // Env
    countByEnv[v.environment || 'UNKNOWN'] = (countByEnv[v.environment || 'UNKNOWN'] || 0) + 1;
    
    // App
    const appName = v.request?.targetApp?.name || 'No App';
    countByApp[appName] = (countByApp[appName] || 0) + 1;
    
    // BU
    const bu = v.request?.targetApp?.department || 'Unknown BU';
    countByBU[bu] = (countByBU[bu] || 0) + 1;

    // Source stats
    if (!sourceStats[src]) {
      sourceStats[src] = { total: 0, severities: {}, statuses: {} };
    }
    sourceStats[src].total++;
    sourceStats[src].severities[v.severity] = (sourceStats[src].severities[v.severity] || 0) + 1;
    sourceStats[src].statuses[v.status] = (sourceStats[src].statuses[v.status] || 0) + 1;

    // Timeline
    if (v.reportedOn) {
      const dt = new Date(v.reportedOn).getTime();
      if (dt < minDate) minDate = dt;
      if (dt > maxDate) maxDate = dt;
    }
    if (v.closedAt && v.reportedOn) {
      const cr = new Date(v.reportedOn).toISOString().split('T')[0];
      const cl = new Date(v.closedAt).toISOString().split('T')[0];
      if (cr === cl) sameDayCreatedClosed++;
    }

    // Assignment
    if (v.assignedToId && v.assignedTo) {
      const name = v.assignedTo.name || 'Unknown';
      assignments[name] = (assignments[name] || 0) + 1;
    } else {
      unassigned++;
    }

    // SLA
    if (v.slaTracking) {
      if (v.slaTracking.isBreached) {
        breachedSla++;
      } else {
        withinSla++;
      }
    }
  });

  // Request mapping
  const requestsBySource: Record<string, { requests: number, vulnsGenerated: number }> = {};
  let reqsWithZeroVulns = 0;
  allRequests.forEach(r => {
    const src = r.source || 'UNKNOWN';
    if (!requestsBySource[src]) {
      requestsBySource[src] = { requests: 0, vulnsGenerated: 0 };
    }
    requestsBySource[src].requests++;
    
    const vulnsForReq = allVulns.filter(v => v.requestId === r.id).length;
    requestsBySource[src].vulnsGenerated += vulnsForReq;
    if (vulnsForReq === 0) reqsWithZeroVulns++;
  });

  const orphanVulns = allVulns.filter(v => !v.requestId).length;

  console.log(JSON.stringify({
    totalVulns, openVulns, closedVulns, countByStatus, countBySeverity, countBySource,
    countByApp, countByEnv, countByBU, sourceStats,
    requestsBySource, reqsWithZeroVulns, orphanVulns,
    assignments, unassigned,
    timeline: {
      minDate: new Date(minDate).toISOString(),
      maxDate: new Date(maxDate).toISOString(),
      sameDayCreatedClosed
    },
    sla: {
      withinSla, breachedSla
    }
  }, null, 2));

  await prisma.$disconnect();
}

runAudit().catch(e => {
  console.error(e);
  process.exit(1);
});
