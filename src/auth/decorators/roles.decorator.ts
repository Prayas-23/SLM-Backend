import { SetMetadata } from '@nestjs/common';
import { UserRole } from '@prisma/client';

export const ROLES_KEY = 'roles';

/**
 * Attach required roles to a route.
 *
 * @example
 * @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
 * @Get('sensitive-endpoint')
 * getSensitiveData() {}
 */
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
