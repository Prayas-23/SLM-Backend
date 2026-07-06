import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { RbacContext } from './query-result.dto';
import { UserRole } from '@prisma/client';

/**
 * RbacQueryService
 *
 * Resolves role-based access constraints for the Query Engine.
 * Builds Prisma WHERE clause fragments that scope results to
 * only what the requesting user is authorised to see.
 *
 * RBAC Matrix:
 *   SECURITY_LEAD        → full access
 *   SECURITY_ANALYST     → full operational access (read)
 *   APPLICATION_OWNER    → own apps + related vulns + related requests
 *   INFRASTRUCTURE_OWNER → own infra + related vulns
 *   READ_ONLY            → full read (same as analyst for queries)
 */
@Injectable()
export class RbacQueryService {
  private readonly logger = new Logger(RbacQueryService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Loads the full RBAC context for a user.
   * Pre-loads owned asset IDs so entity handlers don't need separate queries.
   */
  async buildContext(userId: string): Promise<RbacContext> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id:   true,
        name: true,
        role: true,
        ownedApplications:       { select: { id: true } },
        ownedInfrastructureAssets: { select: { id: true } },
      },
    });

    if (!user) {
      return { userId, userName: 'Unknown', userRole: UserRole.READ_ONLY };
    }

    return {
      userId:        user.id,
      userName:      user.name,
      userRole:      user.role,
      ownedAppIds:   user.ownedApplications.map((a) => a.id),
      ownedInfraIds: user.ownedInfrastructureAssets.map((a) => a.id),
    };
  }

  /**
   * Returns true if this role can see all data without asset-level scoping.
   */
  isGlobalReader(role: string): boolean {
    return (
      role === UserRole.SECURITY_LEAD ||
      role === UserRole.SECURITY_ANALYST ||
      role === UserRole.READ_ONLY
    );
  }

  /**
   * Returns true if the role is permitted to access the AI Query Engine at all.
   * All authenticated roles are permitted read operations.
   */
  canAccessQueryEngine(_role: string): boolean {
    return true;
  }

  // ── WHERE clause fragment builders ────────────────────────────────────────────

  /**
   * Vulnerability WHERE fragment — scope by owned apps + owned infra requests.
   */
  vulnerabilityScope(ctx: RbacContext): Record<string, unknown> | null {
    if (this.isGlobalReader(ctx.userRole)) return null;

    if (ctx.userRole === UserRole.APPLICATION_OWNER) {
      return {
        request: {
          OR: [
            { targetAppId:   { in: ctx.ownedAppIds   ?? [] } },
            { targetInfraId: { in: ctx.ownedInfraIds ?? [] } },
          ],
        },
      };
    }

    if (ctx.userRole === UserRole.INFRASTRUCTURE_OWNER) {
      return {
        request: { targetInfraId: { in: ctx.ownedInfraIds ?? [] } },
      };
    }

    return null;
  }

  /**
   * SecurityRequest WHERE fragment.
   */
  securityRequestScope(ctx: RbacContext): Record<string, unknown> | null {
    if (this.isGlobalReader(ctx.userRole)) return null;

    if (ctx.userRole === UserRole.APPLICATION_OWNER) {
      return { targetAppId: { in: ctx.ownedAppIds ?? [] } };
    }

    if (ctx.userRole === UserRole.INFRASTRUCTURE_OWNER) {
      return { targetInfraId: { in: ctx.ownedInfraIds ?? [] } };
    }

    return null;
  }

  /**
   * Application WHERE fragment.
   */
  applicationScope(ctx: RbacContext): Record<string, unknown> | null {
    if (this.isGlobalReader(ctx.userRole)) return null;

    if (ctx.userRole === UserRole.APPLICATION_OWNER) {
      return { id: { in: ctx.ownedAppIds ?? [] } };
    }

    // INFRASTRUCTURE_OWNER has no direct application access
    return { id: 'FORBIDDEN' }; // Will produce 0 results safely
  }

  /**
   * InfrastructureAsset WHERE fragment.
   */
  infraAssetScope(ctx: RbacContext): Record<string, unknown> | null {
    if (this.isGlobalReader(ctx.userRole)) return null;

    if (ctx.userRole === UserRole.INFRASTRUCTURE_OWNER) {
      return { id: { in: ctx.ownedInfraIds ?? [] } };
    }

    // APPLICATION_OWNER has no direct infra access
    return { id: 'FORBIDDEN' };
  }
}
