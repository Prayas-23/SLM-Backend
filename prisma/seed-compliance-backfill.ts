// =============================================================================
// Compliance Backfill Script
// =============================================================================
//
// One-shot script that maps all existing vulnerabilities (that have no
// VulnerabilityControlMapping yet) to their Security Controls using the
// AutoRuleStrategy.
//
// Usage:
//   npx ts-node prisma/seed-compliance-backfill.ts
//
// Idempotent: safe to re-run. Already-mapped vulnerabilities are skipped.
// =============================================================================

import { PrismaClient } from '@prisma/client';
import { AutoRuleStrategy } from '../src/compliance/strategies/auto-rule.strategy';

const prisma = new PrismaClient();
const autoRule = new AutoRuleStrategy();

async function main() {
  console.log('🔄 Compliance backfill starting...\n');

  // ── 1. Fetch all active, unmapped vulnerabilities ───────────────────────────
  const vulns = await prisma.vulnerability.findMany({
    where: {
      deletedAt: null,
      controlMappings: { none: {} },
    },
    select: { id: true, vulnId: true, type: true },
  });

  console.log(`📋 Found ${vulns.length} unmapped vulnerability(s).\n`);

  if (vulns.length === 0) {
    console.log('✅ Nothing to backfill — all vulnerabilities already mapped.');
    return;
  }

  // ── 2. Pre-load all active SecurityControls for key → id lookup ─────────────
  const allControls = await prisma.securityControl.findMany({
    where: { isActive: true },
    select: { id: true, controlKey: true },
  });
  const controlMap = new Map(allControls.map((c) => [c.controlKey, c.id]));

  console.log(`🔑 Loaded ${allControls.length} active security control(s).\n`);

  // ── 3. Process each vulnerability ──────────────────────────────────────────
  let totalMapped = 0;
  let totalNoMatch = 0;
  let totalErrors = 0;

  for (const vuln of vulns) {
    try {
      const matches = autoRule.match(vuln.type);

      if (matches.length === 0) {
        console.log(`  ⚪ ${vuln.vulnId} | "${vuln.type}" → no match`);
        totalNoMatch++;
        continue;
      }

      let mappedForVuln = 0;
      for (const match of matches) {
        const controlId = controlMap.get(match.controlKey);
        if (!controlId) {
          console.warn(`  ⚠️  ${vuln.vulnId} — controlKey "${match.controlKey}" not in DB`);
          continue;
        }

        await prisma.vulnerabilityControlMapping.upsert({
          where: {
            vulnerabilityId_controlId: {
              vulnerabilityId: vuln.id,
              controlId,
            },
          },
          update: { mappedBy: match.source, confidence: match.confidence },
          create: {
            vulnerabilityId: vuln.id,
            controlId,
            mappedBy: match.source,
            confidence: match.confidence,
          },
        });
        mappedForVuln++;
      }

      const keys = matches.map((m) => m.controlKey).join(', ');
      console.log(`  ✅ ${vuln.vulnId} | "${vuln.type}" → [${keys}] (${mappedForVuln} mapping(s))`);
      totalMapped += mappedForVuln;
    } catch (err) {
      console.error(`  ❌ ${vuln.vulnId} | error: ${(err as Error).message}`);
      totalErrors++;
    }
  }

  // ── 4. Summary ──────────────────────────────────────────────────────────────
  console.log('\n' + '─'.repeat(60));
  console.log(`✅ Backfill complete.`);
  console.log(`   Vulnerabilities processed : ${vulns.length}`);
  console.log(`   Control mappings created  : ${totalMapped}`);
  console.log(`   No rule match (skipped)   : ${totalNoMatch}`);
  console.log(`   Errors                    : ${totalErrors}`);
  console.log('─'.repeat(60) + '\n');
}

main()
  .catch((e) => {
    console.error('❌ Backfill failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
