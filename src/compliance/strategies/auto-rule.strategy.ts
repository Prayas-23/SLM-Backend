// =============================================================================
// AutoRule Mapping Strategy
// =============================================================================
//
// Implements keyword-based vulnerability type → SecurityControl matching.
//
// Algorithm:
//   1. Normalise vulnerability type to lowercase.
//   2. Iterate every MappingRule in MAPPING_RULES.
//   3. For each rule, test whether ANY of its keywords appear as substrings
//      in the normalised type string.
//   4. When a rule fires, emit one ControlMatch per controlKey in the rule.
//   5. De-duplicate by controlKey — highest confidence wins on collision.
//
// Confidence assignment (per rule):
//   HIGH   — exact canonical class match (e.g. "SQL Injection" → INPUT_VALIDATION)
//   MEDIUM — partial or broader keyword match
//   LOW    — never generated here; reserved for AIStrategy
// =============================================================================

import { Injectable } from '@nestjs/common';
import { MappingSource } from '@prisma/client';
import { MAPPING_RULES } from './mapping-rule.config';
import { ControlMatch, IMappingStrategy } from './mapping-strategy.interface';

// Confidence ordering for de-duplication (higher index = higher priority)
const CONFIDENCE_RANK: Record<string, number> = { LOW: 0, MEDIUM: 1, HIGH: 2 };

@Injectable()
export class AutoRuleStrategy implements IMappingStrategy {
  readonly strategyName = 'AUTO_RULE';

  /**
   * Returns deduplicated ControlMatch entries for the given vulnerability type.
   * Case-insensitive substring matching against all rules in MAPPING_RULES.
   */
  match(vulnerabilityType: string): ControlMatch[] {
    const normalised = vulnerabilityType.toLowerCase();
    const byKey = new Map<string, ControlMatch>();

    for (const rule of MAPPING_RULES) {
      const fires = rule.keywords.some((kw) => normalised.includes(kw.toLowerCase()));
      if (!fires) continue;

      for (const controlKey of rule.controlKeys) {
        const existing = byKey.get(controlKey);
        const incomingRank = CONFIDENCE_RANK[rule.confidence];

        if (!existing || incomingRank > CONFIDENCE_RANK[existing.confidence]) {
          byKey.set(controlKey, {
            controlKey,
            confidence: rule.confidence,
            source: 'AUTO_RULE' as MappingSource,
          });
        }
      }
    }

    return Array.from(byKey.values());
  }
}
