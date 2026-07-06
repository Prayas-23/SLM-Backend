import { Module } from '@nestjs/common';
import { ContinuousScanController } from './continuous-scan.controller';
import { ContinuousScanService } from './continuous-scan.service';
import { ContinuousScanIngestionService } from './continuous-scan-ingestion.service';
import { PrismaModule } from '../prisma/prisma.module';
import { ComplianceModule } from '../compliance/compliance.module';

@Module({
  imports: [PrismaModule, ComplianceModule],
  controllers: [ContinuousScanController],
  providers: [ContinuousScanService, ContinuousScanIngestionService],
  exports: [ContinuousScanService],
})
export class ContinuousScanModule {}

