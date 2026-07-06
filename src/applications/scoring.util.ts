export interface ScoringAppInput {
  environment: string;
  criticality?: string | null;
  internetAccessible: boolean;
  lastVaptDate?: Date | null;
  securityRequests?: {
    initiatedOn?: Date;
    startedAt?: Date;
    vulnerabilities?: {
      severity: string;
      status: string;
      slaDueDate?: Date | null;
      reportedOn?: Date | null;
      shortDesc?: string | null;
    }[];
  }[];
}

export function calculateApplicationScores(app: ScoringAppInput) {
  const now = new Date();
  
  // Flatten vulnerabilities
  const allVulns = app.securityRequests?.flatMap(req => req.vulnerabilities || []) || [];
  const openVulns = allVulns.filter(v => v.status !== 'CLOSED' && v.status !== 'PATCHED');
  const closedVulns = allVulns.filter(v => v.status === 'CLOSED' || v.status === 'PATCHED');
  
  const critVulns = openVulns.filter(v => v.severity === 'CRITICAL');
  const highVulns = openVulns.filter(v => v.severity === 'HIGH');
  const medVulns = openVulns.filter(v => v.severity === 'MEDIUM');
  const lowVulns = openVulns.filter(v => v.severity === 'LOW');
  
  const vulnsWithSla = openVulns.filter(v => v.slaDueDate);
  const overdueVulns = vulnsWithSla.filter(v => new Date(v.slaDueDate!) < now);
  const overdueCount = overdueVulns.length;
  
  const staleVulns = openVulns.filter(v => {
    if (!v.reportedOn) return false;
    const ageDays = (now.getTime() - new Date(v.reportedOn).getTime()) / (1000 * 3600 * 24);
    return ageDays > 90;
  });
  const staleCount = staleVulns.length;

  // Recent Assessment?
  let lastAssessmentDate = app.lastVaptDate ? new Date(app.lastVaptDate) : null;
  if (!lastAssessmentDate) {
    const vaptReqs = app.securityRequests?.filter(r => r.initiatedOn) || [];
    if (vaptReqs.length > 0) {
      const dates = vaptReqs.map(r => new Date(r.initiatedOn!).getTime());
      lastAssessmentDate = new Date(Math.max(...dates));
    }
  }
  
  let isStaleAssessment = false;
  let isRecentAssessment = false;
  if (lastAssessmentDate) {
    const ageDays = (now.getTime() - lastAssessmentDate.getTime()) / (1000 * 3600 * 24);
    if (ageDays > 365) isStaleAssessment = true;
    if (ageDays <= 180) isRecentAssessment = true;
  } else {
    isStaleAssessment = true; // No assessment = stale
  }

  // --- RISK SCORE ---
  let riskScore = 0;
  const riskDrivers: string[] = [];

  // Contextual
  if (app.environment === 'PRODUCTION') {
    riskScore += 10;
    riskDrivers.push('+10 Production Environment');
  }
  if (app.internetAccessible) {
    riskScore += 10;
    riskDrivers.push('+10 Internet Facing Exposure');
  }
  if (app.criticality === 'Critical' || app.criticality === 'High') {
    riskScore += 10;
    riskDrivers.push('+10 Critical Application Tier');
  }
  
  // Threat
  if (critVulns.length > 0) {
    let critPoints = 0;
    if (critVulns.length >= 1) { critPoints += 20; riskDrivers.push('+20 First Critical Vulnerability'); }
    if (critVulns.length >= 2) { critPoints += 10; riskDrivers.push('+10 Second Critical Vulnerability'); }
    if (critVulns.length >= 3) { critPoints += 5; riskDrivers.push('+5 Third Critical Vulnerability'); }
    if (critVulns.length >= 4) {
      const additional = Math.min((critVulns.length - 3) * 2, 10);
      critPoints += additional;
      riskDrivers.push(`+${additional} Additional Critical Vulnerabilities`);
    }
    riskScore += critPoints;
  }
  
  if (highVulns.length > 0) {
    const highPoints = Math.min(highVulns.length * 5, 20);
    riskScore += highPoints;
    riskDrivers.push(`+${highPoints} High Vulnerabilities (${highVulns.length})`);
  }
  
  if (medVulns.length > 0) {
    const medPoints = Math.min(medVulns.length * 1, 10);
    riskScore += medPoints;
    riskDrivers.push(`+${medPoints} Medium Vulnerabilities (${medVulns.length})`);
  }
  
  if (lowVulns.length > 0) {
    const lowPoints = Math.min(lowVulns.length * 0.25, 5);
    riskScore += lowPoints;
    riskDrivers.push(`+${lowPoints} Low Vulnerabilities (${lowVulns.length})`);
  }

  // Operational
  if (overdueCount > 0) {
    const slaPoints = Math.min(overdueCount * 2, 15);
    riskScore += slaPoints;
    riskDrivers.push(`+${slaPoints} SLA Breaches (${overdueCount} overdue findings)`);
  }
  
  if (isStaleAssessment) {
    riskScore += 10;
    riskDrivers.push('+10 Stale Assessment (>1 Year)');
  }
  
  const finalRiskScore = Math.min(Math.round(riskScore), 100);
  
  let riskClassification = 'Low';
  if (finalRiskScore > 80) riskClassification = 'Critical';
  else if (finalRiskScore > 60) riskClassification = 'High';
  else if (finalRiskScore > 40) riskClassification = 'Elevated';
  else if (finalRiskScore > 20) riskClassification = 'Moderate';

  // --- HEALTH SCORE ---
  let healthPositives = 0;
  let healthNegatives = 0;
  const positiveDrivers: string[] = [];
  const negativeDrivers: string[] = [];
  
  // Positives
  const allVulnsWithSla = allVulns.filter(v => v.slaDueDate);
  let slaCompliancePct = 100;
  if (allVulnsWithSla.length > 0) {
    const withinSla = allVulnsWithSla.filter(v => v.status === 'CLOSED' ? true : new Date(v.slaDueDate!) >= now);
    slaCompliancePct = (withinSla.length / allVulnsWithSla.length) * 100;
  }
  const healthSlaPoints = Math.round(slaCompliancePct * 0.40);
  healthPositives += healthSlaPoints;
  positiveDrivers.push(`+${healthSlaPoints} SLA Compliance (${Math.round(slaCompliancePct)}%)`);

  let fixRatePct = 100;
  if (allVulns.length > 0) {
    fixRatePct = (closedVulns.length / allVulns.length) * 100;
  }
  const fixPoints = Math.round(fixRatePct * 0.30);
  healthPositives += fixPoints;
  positiveDrivers.push(`+${fixPoints} Remediation Rate (${Math.round(fixRatePct)}% fixed)`);
  
  if (isRecentAssessment) {
    healthPositives += 15;
    positiveDrivers.push('+15 Recent Assessment (<6 months)');
  }
  
  if (critVulns.length === 0) {
    healthPositives += 15;
    positiveDrivers.push('+15 Zero Criticals Bonus');
  }
  
  // Negatives
  if (critVulns.length > 0) {
    const critPenalty = critVulns.length * 10;
    healthNegatives += critPenalty;
    negativeDrivers.push(`-${critPenalty} Critical Vulnerabilities (${critVulns.length})`);
  }
  
  if (overdueCount > 0) {
    const breachPenalty = overdueCount * 5;
    healthNegatives += breachPenalty;
    negativeDrivers.push(`-${breachPenalty} SLA Breaches (${overdueCount})`);
  }
  
  if (staleCount > 0) {
    const stalePenalty = staleCount * 2;
    healthNegatives += stalePenalty;
    negativeDrivers.push(`-${stalePenalty} Stale Vulnerabilities (>90 days)`);
  }
  
  const descCounts: Record<string, number> = {};
  for (const v of allVulns) {
    if (v.shortDesc) {
      descCounts[v.shortDesc] = (descCounts[v.shortDesc] || 0) + 1;
    }
  }
  let repeatCount = 0;
  for (const key in descCounts) {
    if (descCounts[key] > 1) {
      repeatCount += (descCounts[key] - 1);
    }
  }
  
  if (repeatCount > 0) {
    const repeatPenalty = repeatCount * 5;
    healthNegatives += repeatPenalty;
    negativeDrivers.push(`-${repeatPenalty} Repeat Findings (${repeatCount})`);
  }
  
  const finalHealthScore = Math.max(Math.round(healthPositives - healthNegatives), 0);
  
  let healthClassification = 'Critical';
  if (finalHealthScore >= 90) healthClassification = 'Excellent';
  else if (finalHealthScore >= 75) healthClassification = 'Good';
  else if (finalHealthScore >= 60) healthClassification = 'Fair';
  else if (finalHealthScore >= 40) healthClassification = 'Poor';

  riskDrivers.sort((a, b) => {
    const matchA = a.match(/\+(\d+)/);
    const matchB = b.match(/\+(\d+)/);
    const valA = matchA ? parseInt(matchA[1]) : 0;
    const valB = matchB ? parseInt(matchB[1]) : 0;
    return valB - valA;
  });
  
  positiveDrivers.sort((a, b) => {
    const matchA = a.match(/\+(\d+)/);
    const matchB = b.match(/\+(\d+)/);
    const valA = matchA ? parseInt(matchA[1]) : 0;
    const valB = matchB ? parseInt(matchB[1]) : 0;
    return valB - valA;
  });

  return {
    riskScore: finalRiskScore,
    riskClassification,
    riskDrivers,
    healthScore: finalHealthScore,
    healthClassification,
    healthDrivers: {
      positive: positiveDrivers,
      negative: negativeDrivers,
    }
  };
}
