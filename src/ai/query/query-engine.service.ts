import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { IntentDto, AIEntity, AIOperation } from '../dto/intent.dto';
import { QueryResult, RbacContext, makeError } from './query-result.dto';
import { QueryBuilderService } from './query-builder.service';
import { RbacQueryService } from './rbac-query.service';
import { AuditAction, AuditEntityType } from '@prisma/client';

/**
 * QueryEngineService
 *
 * The top-level orchestrator for Phase 2.2.
 *
 * Responsibilities:
 *   1. Load the full RBAC context for the requesting user.
 *   2. Guard unsupported / UNKNOWN intents before touching the DB.
 *   3. Delegate to QueryBuilderService for the actual Prisma query.
 *   4. Wrap the result into a standardised QueryResult.
 *   5. Write an audit log entry for every execution.
 *
 * What it does NOT do:
 *   - Generate SQL
 *   - Call Gemini / any LLM
 *   - Generate natural language responses
 *   - Return partial data on RBAC failure
 */
@Injectable()
export class QueryEngineService {
  private readonly logger = new Logger(QueryEngineService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly rbac: RbacQueryService,
    private readonly builder: QueryBuilderService,
  ) {}

  /**
   * Execute a validated IntentDto as a safe Prisma query.
   *
   * @param intent Validated IntentDto from the Intent Detection Engine.
   * @param actor  Requesting user identity.
   * @param page   Pagination page (default 1).
   * @param limit  Page size (default 20, max 100).
   */
  async execute<T = Record<string, unknown>>(
    intent: IntentDto,
    actor: { id: string; name: string },
    page  = 1,
    limit = 20,
  ): Promise<QueryResult<T>> {
    const startedAt = Date.now();
    const safeLimit = Math.min(limit, 100);

    // ── Guard: UNKNOWN intents are rejected before DB touch ──────────────────
    if (intent.operation === AIOperation.UNKNOWN || intent.entity === AIEntity.UNKNOWN) {
      return makeError<T>(
        intent.entity,
        intent.operation,
        intent.filters,
        { id: actor.id, role: 'UNKNOWN' },
        'Intent could not be resolved. Please rephrase your query.',
        startedAt,
      ) as QueryResult<T>;
    }

    // ── Guard: EXPLAIN and HELP do not require DB queries ────────────────────
    if (intent.operation === AIOperation.EXPLAIN || intent.operation === AIOperation.HELP) {
      return {
        success:      true,
        entity:       intent.entity,
        operation:    intent.operation,
        totalRecords: 0,
        data:         [],
        metadata: {
          executionTimeMs: Date.now() - startedAt,
          filtersApplied:  intent.filters,
          actorId:         actor.id,
          actorRole:       'N/A',
        },
      };
    }

    // ── Load RBAC context ─────────────────────────────────────────────────────
    let ctx: RbacContext;
    try {
      ctx = await this.rbac.buildContext(actor.id);
    } catch (err) {
      this.logger.error(`RBAC context load failed: ${err instanceof Error ? err.message : String(err)}`);
      return makeError<T>(intent.entity, intent.operation, intent.filters, { id: actor.id, role: 'UNKNOWN' }, 'Failed to load access context.', startedAt) as QueryResult<T>;
    }

    // ── Execute query via builder ─────────────────────────────────────────────
    let result: { data: unknown[]; total: number };
    try {
      result = await this.builder.execute(intent, ctx, page, safeLimit);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`Query execution failed for entity=${intent.entity}: ${msg}`);
      await this.audit(intent, ctx, 0, false, Date.now() - startedAt);
      return makeError<T>(intent.entity, intent.operation, intent.filters, { id: actor.id, role: ctx.userRole }, msg, startedAt) as QueryResult<T>;
    }

    const executionTimeMs = Date.now() - startedAt;

    await this.audit(intent, ctx, result.total, true, executionTimeMs);

    return {
      success:      true,
      entity:       intent.entity,
      operation:    intent.operation,
      totalRecords: result.total,
      data:         result.data as T[],
      metadata: {
        executionTimeMs,
        filtersApplied: intent.filters,
        actorId:        ctx.userId,
        actorRole:      ctx.userRole,
      },
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private async audit(
    intent:          IntentDto,
    ctx:             RbacContext,
    resultCount:     number,
    success:         boolean,
    executionTimeMs: number,
  ) {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorId:    ctx.userId,
          actorName:  ctx.userName,
          entityType: AuditEntityType.USER,
          entityId:   'ai-query-engine',
          action:     AuditAction.CREATED,
          metadata: {
            event:    'AI_QUERY_EXECUTED',
            entity:   intent.entity,
            operation: intent.operation,
            filters:  intent.filters,
            confidence: intent.confidence,
            resultCount,
            success,
            executionTimeMs,
          } as never,
        },
      });
    } catch (err) {
      this.logger.error(`Query audit log failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
