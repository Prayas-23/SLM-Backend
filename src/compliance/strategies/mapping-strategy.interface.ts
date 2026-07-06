// =============================================================================
// Strategy Interface
// =============================================================================
//
// All mapping strategies implement this interface.
// Adding a new strategy (ManualStrategy, AIStrategy) requires only:
//   1. Implementing IMappingStrategy
//   2. Registering it in ComplianceMappingService
// No modification to existing strategies is ever required.
// =============================================================================

import { MappingConfidence, MappingSource } from '@prisma/client';

export interface ControlMatch {
  controlKey: string;
  confidence: MappingConfidence;
  source: MappingSource;
}

export interface IMappingStrategy {
  readonly strategyName: string;
  match(vulnerabilityType: string): ControlMatch[];
}
