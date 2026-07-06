import { Module } from '@nestjs/common';
import { ComplianceMappingService } from './compliance-mapping.service';
import { AutoRuleStrategy } from './strategies/auto-rule.strategy';
import { PrismaModule } from '../prisma/prisma.module';

/**
 * ComplianceModule
 *
 * Provides ComplianceMappingService to any module that imports it.
 * PrismaModule is imported for DB access.
 *
 * Future strategies (ManualStrategy, AIStrategy):
 *   1. Create the class implementing IMappingStrategy.
 *   2. Add to the providers array here.
 *   3. Inject into ComplianceMappingService.strategies.
 *   No other changes required.
 */
@Module({
  imports: [PrismaModule],
  providers: [ComplianceMappingService, AutoRuleStrategy],
  exports: [ComplianceMappingService],
})
export class ComplianceModule {}
