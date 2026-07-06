import { AIEntity, AIOperation, IntentFilters } from '../dto/intent.dto';

/**
 * QueryResult<T> — the universal output of the Query Engine.
 *
 * Passed directly to the Phase 2.3 Prompt Builder.
 * Contains verified data only — no LLM content.
 */
export interface QueryResult<T = Record<string, unknown>> {
  success:      boolean;
  entity:       AIEntity;
  operation:    AIOperation;
  totalRecords: number;
  data:         T[];
  error?:       string;
  metadata: {
    executionTimeMs:  number;
    filtersApplied:   IntentFilters;
    actorId:          string;
    actorRole:        string;
  };
}

/**
 * RbacContext — caller identity injected at every query boundary.
 * The Query Engine never trusts the caller to self-declare permissions.
 */
export interface RbacContext {
  userId:   string;
  userName: string;
  userRole: string;
  /** Owned application IDs — pre-loaded for APPLICATION_OWNER enforcement */
  ownedAppIds?:   string[];
  /** Owned infra IDs — pre-loaded for INFRASTRUCTURE_OWNER enforcement */
  ownedInfraIds?: string[];
}

export function makeError<T>(
  entity:      AIEntity,
  operation:   AIOperation,
  filters:     IntentFilters,
  actor:       { id: string; role: string },
  msg:         string,
  startedAt:   number,
): QueryResult<T> {
  return {
    success:      false,
    entity,
    operation,
    totalRecords: 0,
    data:         [],
    error:        msg,
    metadata: {
      executionTimeMs:  Date.now() - startedAt,
      filtersApplied:   filters,
      actorId:          actor.id,
      actorRole:        actor.role,
    },
  };
}
