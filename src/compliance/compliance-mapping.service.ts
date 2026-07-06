// =============================================================================
// ComplianceMappingService
// =============================================================================
//
// Single entry point for all vulnerability → SecurityControl mapping.
//
// Responsibilities:
//   1. mapVulnerability(id, type)  — called after every vulnerability creation
//   2. backfillAll()               — one-shot idempotent backfill for existing vulns
//
// Strategy orchestration:
//   Strategies are injected as a list. Each active strategy is executed in order.
//   Results from all strategies are merged; for collisions on the same controlKey
//   the highest-confidence mapping wins.
//
//   Adding a new strategy (ManualStrategy, AIStrategy):
//     1. Implement IMappingStrategy.
//     2. Add the class to the `strategies` array in the constructor.
//     3. Register the class as a provider in ComplianceModule.
//   No existing code changes required.
//
// Idempotency:
//   All inserts use upsert on (vulnerabilityId, controlId) @@unique constraint.
//   Running mapVulnerability twice for the same vulnerability is safe.
// =============================================================================

import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AutoRuleStrategy } from './strategies/auto-rule.strategy';
import { ControlMatch } from './strategies/mapping-strategy.interface';

@Injectable()
export class ComplianceMappingService {
  private readonly logger = new Logger(ComplianceMappingService.name);

  /**
   * Active strategies evaluated for every vulnerability.
   * Each strategy is tried in order; results are merged before persisting.
   *
   * Future: inject additional strategies here (ManualStrategy, AIStrategy).
   */
  private readonly strategies = [this.autoRule];

  constructor(
    private readonly prisma: PrismaService,
    private readonly autoRule: AutoRuleStrategy,
  ) {}

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Maps a single vulnerability to all matched SecurityControls.
   * Called automatically after every vulnerability creation event.
   *
   * @param vulnerabilityId UUID of the newly created vulnerability
   * @param vulnerabilityType The free-text `type` field (e.g. "SQL Injection")
   * @returns Summary of what was mapped
   */
  async mapVulnerability(
    vulnerabilityId: string,
    vulnerabilityType: string,
  ): Promise<{ mapped: number; controlKeys: string[] }> {
    const start = Date.now();

    try {
      // ── 1. Run all active strategies ─────────────────────────────────────────
      const matches = this.mergeMatches(
        this.strategies.flatMap((s) => s.match(vulnerabilityType)),
      );

      if (matches.length === 0) {
        this.logger.debug(
          `[${this.strategies.map((s) => s.strategyName).join(',')}] ` +
          `vuln=${vulnerabilityId} type="${vulnerabilityType}" → no control matches`,
        );
        return { mapped: 0, controlKeys: [] };
      }

      // ── 2. Resolve controlKey → SecurityControl.id ───────────────────────────
      const controlKeys = matches.map((m) => m.controlKey);
      const controls = await this.prisma.securityControl.findMany({
        where: { controlKey: { in: controlKeys }, isActive: true },
        select: { id: true, controlKey: true },
      });

      const controlMap = new Map(controls.map((c) => [c.controlKey, c.id]));
      const matchMap = new Map(matches.map((m) => [m.controlKey, m]));

      // ── 3. Upsert one VulnerabilityControlMapping per resolved control ────────
      let persistedCount = 0;
      const persistedKeys: string[] = [];

      for (const control of controls) {
        const match = matchMap.get(control.controlKey)!;

        await this.prisma.vulnerabilityControlMapping.upsert({
          where: {
            vulnerabilityId_controlId: {
              vulnerabilityId,
              controlId: control.id,
            },
          },
          // On conflict: upgrade confidence if the new value is higher
          update: {
            mappedBy: match.source,
            confidence: match.confidence,
          },
          create: {
            vulnerabilityId,
            controlId: control.id,
            mappedBy: match.source,
            confidence: match.confidence,
          },
        });

        persistedCount++;
        persistedKeys.push(control.controlKey);
      }

      const ms = Date.now() - start;
      this.logger.log(
        `[AutoRule] vuln=${vulnerabilityId} type="${vulnerabilityType}" ` +
        `→ mapped ${persistedCount} control(s): [${persistedKeys.join(', ')}] (${ms}ms)`,
      );

      // Log unresolved keys (controlKey in rules but not seeded in DB)
      const unresolvedKeys = controlKeys.filter((k) => !controlMap.has(k));
      if (unresolvedKeys.length > 0) {
        this.logger.warn(
          `[AutoRule] vuln=${vulnerabilityId} — unresolved controlKeys (not found in security_controls): ` +
          `[${unresolvedKeys.join(', ')}]. Check seed data.`,
        );
      }

      return { mapped: persistedCount, controlKeys: persistedKeys };
    } catch (err) {
      const ms = Date.now() - start;
      this.logger.error(
        `[AutoRule] FAILED vuln=${vulnerabilityId} type="${vulnerabilityType}" (${ms}ms): ${(err as Error).message}`,
        (err as Error).stack,
      );
      // Never throw — mapping failure must NOT interrupt the vulnerability creation flow
      return { mapped: 0, controlKeys: [] };
    }
  }

  /**
   * Idempotent backfill: processes every existing, non-deleted vulnerability
   * that has not yet been mapped to any SecurityControl.
   *
   * Designed to be called once from a CLI script or admin endpoint.
   * Safe to re-run — all inserts use upsert.
   *
   * @returns Summary counts
   */
  async backfillAll(): Promise<{
    total: number;
    processed: number;
    mapped: number;
    skipped: number;
    errors: number;
  }> {
    this.logger.log('[Backfill] Starting compliance mapping backfill...');
    const start = Date.now();

    // Fetch all active vulns that have NO mapping yet (unmapped only, to be
    // efficient on repeated runs — already-mapped vulns are skipped).
    const vulns = await this.prisma.vulnerability.findMany({
      where: {
        deletedAt: null,
        controlMappings: { none: {} },
      },
      select: { id: true, type: true, vulnId: true },
    });

    const total = vulns.length;
    let processed = 0;
    let totalMapped = 0;
    let skipped = 0;
    let errors = 0;

    this.logger.log(`[Backfill] Found ${total} unmapped vulnerability(s) to process.`);

    for (const vuln of vulns) {
      try {
        const result = await this.mapVulnerability(vuln.id, vuln.type);
        processed++;
        totalMapped += result.mapped;
        if (result.mapped === 0) skipped++;
      } catch {
        errors++;
        this.logger.error(`[Backfill] Unexpected error for vuln=${vuln.id} (${vuln.vulnId})`);
      }
    }

    const ms = Date.now() - start;
    this.logger.log(
      `[Backfill] Complete in ${ms}ms. ` +
      `total=${total} processed=${processed} mapped_rows=${totalMapped} ` +
      `no_match=${skipped} errors=${errors}`,
    );

    return { total, processed, mapped: totalMapped, skipped, errors };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Merges matches from multiple strategies.
   * When two strategies both match the same controlKey, the higher-confidence
   * entry wins. Analyst (MANUAL/HIGH) always beats AUTO_RULE.
   */
  private mergeMatches(matches: ControlMatch[]): ControlMatch[] {
    const RANK: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };
    const best = new Map<string, ControlMatch>();

    for (const m of matches) {
      const existing = best.get(m.controlKey);
      if (!existing || RANK[m.confidence] > RANK[existing.confidence]) {
        best.set(m.controlKey, m);
      }
    }

    return Array.from(best.values());
  }
}
