import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  const applications = await prisma.application.findMany({
    where: { 
      deletedAt: null, 
      name: { contains: 'internet-banking' } 
    },
    include: {
      owner: { select: { name: true } },
      securityRequests: {
        where: { deletedAt: null },
        include: {
          vulnerabilities: {
            where: { deletedAt: null },
            select: { id: true, severity: true, status: true, slaDueDate: true },
          },
        },
      },
    },
  });

  const now = new Date();
  
  if (applications.length === 0) {
    console.log("No application matching 'internet-banking' found.");
    return;
  }

  for (const app of applications) {
    const allVulns = app.securityRequests?.flatMap((req: any) => req.vulnerabilities) || [];
    const totalVulns = allVulns.length;
    const closedVulnCount = allVulns.filter((v: any) => v.status === 'CLOSED').length;
    
    const openVulnCount = totalVulns - closedVulnCount;
    // Note: The logic in dashboard.service.ts treats HIGH and CRITICAL identically as 'critVulnCount'
    const critVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
    
    const vulnsWithSla = allVulns.filter((v: any) => v.status !== 'CLOSED' && v.slaDueDate);
    const withinSla = vulnsWithSla.filter((v: any) => new Date(v.slaDueDate!) >= new Date()).length;
    const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
    
    const patchCompliancePct = totalVulns > 0 ? Math.round((closedVulnCount / totalVulns) * 100) : 100;
    
    const isVaptOverdue = app.nextVaptDate && app.nextVaptDate < now;
    
    let rawScore = 50 + (slaCompliancePct * 0.5) - (critVulnCount * 5) - ((openVulnCount - critVulnCount) * 1);
    if (isVaptOverdue) rawScore -= 10;
    
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));

    console.log(`\n======================================================`);
    console.log(`--- TRACE FOR: ${app.name} ---`);
    console.log(`======================================================`);
    console.log(`Total vulnerabilities associated: ${totalVulns}`);
    console.log(`Open vulnerabilities:             ${openVulnCount}`);
    console.log(`Closed vulnerabilities:           ${closedVulnCount}`);
    console.log(`Critical/High vulnerabilities:    ${critVulnCount}`);
    console.log(`------------------------------------------------------`);
    console.log(`Vulnerabilities with SLA:         ${vulnsWithSla.length}`);
    console.log(`Vulnerabilities within SLA:       ${withinSla}`);
    console.log(`SLA compliance percentage:        ${slaCompliancePct}%`);
    console.log(`Patch compliance percentage:      ${patchCompliancePct}%`);
    console.log(`------------------------------------------------------`);
    console.log(`Last VAPT date:                   ${app.lastVaptDate}`);
    console.log(`Next VAPT date:                   ${app.nextVaptDate}`);
    console.log(`Is VAPT Overdue?:                 ${isVaptOverdue}`);
    console.log(`------------------------------------------------------`);
    console.log(`Intermediate Formula:`);
    console.log(`50 + (${slaCompliancePct} * 0.5) - (${critVulnCount} * 5) - ((${openVulnCount} - ${critVulnCount}) * 1) - (Overdue Penalty: ${isVaptOverdue ? 10 : 0})`);
    console.log(`Raw Computed Score:               ${rawScore}`);
    console.log(`Final Rounded & Clamped Score:    ${score}`);
    console.log(`======================================================\n`);
  }
}

main().finally(() => prisma.$disconnect());
