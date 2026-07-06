import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma/prisma.module';
import { ScanFindingsService } from './scan-findings.service';
import { ScanFindingsController } from './scan-findings.controller';

@Module({
  imports: [PrismaModule],
  controllers: [ScanFindingsController],
  providers: [ScanFindingsService],
  exports: [ScanFindingsService],
})
export class ScanFindingsModule {}
