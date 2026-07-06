import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { IntentDto, AIEntity, AIOperation } from '../dto/intent.dto';
import { RbacContext } from './query-result.dto';
import { VulnerabilityHandler }         from './entity-handlers/vulnerability.handler';
import { SecurityRequestHandler }        from './entity-handlers/security-request.handler';
import { ApplicationHandler }            from './entity-handlers/application.handler';
import { InfrastructureAssetHandler }    from './entity-handlers/infrastructure-asset.handler';
import { ContinuousScanFindingHandler }  from './entity-handlers/continuous-scan-finding.handler';
import { CloudResourceHandler }          from './entity-handlers/cloud-resource.handler';
import { DashboardHandler }              from './entity-handlers/dashboard.handler';
import { RbacQueryService }              from './rbac-query.service';

/**
 * QueryBuilderService
 *
 * Routes an IntentDto to the correct entity handler.
 * RBAC scoping is applied before every query.
 * Prisma is the ONLY database access layer used here.
 * No raw SQL. No LLM access. No privilege escalation.
 */
@Injectable()
export class QueryBuilderService {
  private readonly logger = new Logger(QueryBuilderService.name);

  // ── Lazy-init handlers (constructor injection via Prisma) ──────────────────
  private readonly handlers: Map<AIEntity, unknown>;

  constructor(
    private readonly prisma: PrismaService,
    private readonly rbac: RbacQueryService,
  ) {
    this.handlers = new Map<AIEntity, EntityHandler>([
      [AIEntity.VULNERABILITY,           new VulnerabilityHandler(prisma)],
      [AIEntity.SECURITY_REQUEST,        new SecurityRequestHandler(prisma)],
      [AIEntity.APPLICATION,             new ApplicationHandler(prisma)],
      [AIEntity.INFRASTRUCTURE_ASSET,    new InfrastructureAssetHandler(prisma)],
      [AIEntity.CONTINUOUS_SCAN_FINDING, new ContinuousScanFindingHandler(prisma)],
      [AIEntity.CLOUD_RESOURCE,          new CloudResourceHandler(prisma)],
    ] as Array<[AIEntity, EntityHandler]>);
  }

  /**
   * Executes the query described by the IntentDto.
   * Returns { data, total } without wrapping — the QueryEngineService wraps it into QueryResult.
   */
  async execute(
    intent: IntentDto,
    ctx: RbacContext,
    page = 1,
    limit = 20,
  ): Promise<{ data: unknown[]; total: number }> {
    const { entity, operation, filters } = intent;

    // ── Dashboard is a special aggregate case ────────────────────────────────
    if (entity === AIEntity.DASHBOARD) {
      const handler = new DashboardHandler(this.prisma);
      if (operation === AIOperation.ANALYZE) {
        return handler.analyze(filters.environment);
      }
      return handler.summary(filters.environment);
    }

    // ── GENERAL_SECURITY — no DB query needed in Phase 2.2 ──────────────────
    if (entity === AIEntity.GENERAL_SECURITY) {
      return { data: [], total: 0 };
    }

    // ── UNKNOWN → return empty ───────────────────────────────────────────────
    if (entity === AIEntity.UNKNOWN || operation === AIOperation.UNKNOWN) {
      return { data: [], total: 0 };
    }

    // ── Resolve RBAC scope fragment ──────────────────────────────────────────
    const rbacWhere = this.resolveRbacWhere(entity, ctx);

    // ── Route to entity handler ──────────────────────────────────────────────
    const handler = this.handlers.get(entity) as EntityHandler | undefined;
    if (!handler) {
      this.logger.warn(`No handler registered for entity: ${entity}`);
      return { data: [], total: 0 };
    }

    switch (operation) {
      case AIOperation.LIST:    return handler.list(filters, rbacWhere, page, limit);
      case AIOperation.COUNT:   return handler.count(filters, rbacWhere);
      case AIOperation.SUMMARY: return handler.summary(filters, rbacWhere);
      case AIOperation.ANALYZE: return handler.analyze(filters, rbacWhere);
      case AIOperation.COMPARE:
        // COMPARE: run two separate queries (e.g., PRODUCTION vs PRE_PRODUCTION)
        return this.executeCompare(handler, intent, ctx);
      default:
        this.logger.warn(`Unsupported operation: ${operation}`);
        return { data: [], total: 0 };
    }
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private resolveRbacWhere(entity: AIEntity, ctx: RbacContext): Record<string, unknown> | null {
    switch (entity) {
      case AIEntity.VULNERABILITY:
        return this.rbac.vulnerabilityScope(ctx);
      case AIEntity.SECURITY_REQUEST:
        return this.rbac.securityRequestScope(ctx);
      case AIEntity.APPLICATION:
        return this.rbac.applicationScope(ctx);
      case AIEntity.INFRASTRUCTURE_ASSET:
        return this.rbac.infraAssetScope(ctx);
      default:
        return null; // CVS, Cloud — all authenticated roles can see all
    }
  }

  private async executeCompare(
    handler: EntityHandler,
    intent: IntentDto,
    ctx: RbacContext,
  ): Promise<{ data: unknown[]; total: number }> {
    const rbacWhere = this.resolveRbacWhere(intent.entity, ctx);

    // Compare production vs pre-production by default
    const [prodResult, preprodResult] = await Promise.all([
      handler.summary({ ...intent.filters, environment: 'PRODUCTION' }, rbacWhere),
      handler.summary({ ...intent.filters, environment: 'PRE_PRODUCTION' }, rbacWhere),
    ]);

    return {
      data: [
        { label: 'PRODUCTION',     ...prodResult },
        { label: 'PRE_PRODUCTION', ...preprodResult },
      ],
      total: 2,
    };
  }
}

// ── Shared handler interface (local, not exported) ────────────────────────────
interface EntityHandler {
  list(filters: Record<string, string | undefined>, rbacWhere: Record<string, unknown> | null, page?: number, limit?: number): Promise<{ data: unknown[]; total: number }>;
  count(filters: Record<string, string | undefined>, rbacWhere: Record<string, unknown> | null): Promise<{ data: unknown[]; total: number }>;
  summary(filters: Record<string, string | undefined>, rbacWhere: Record<string, unknown> | null): Promise<{ data: unknown[]; total: number }>;
  analyze(filters: Record<string, string | undefined>, rbacWhere: Record<string, unknown> | null): Promise<{ data: unknown[]; total: number }>;
}
