import { Module } from '@nestjs/common';
import { MulterModule } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { VulnerabilitiesService } from './vulnerabilities.service';
import { VulnerabilitiesController } from './vulnerabilities.controller';
import { VulnerabilityWorkflowValidator } from './workflow/vulnerability-workflow.validator';
import { NotificationsModule } from '../notifications/notifications.module';
import { ComplianceModule } from '../compliance/compliance.module';

@Module({
  imports: [MulterModule.register({ storage: memoryStorage() }), NotificationsModule, ComplianceModule],
  controllers: [VulnerabilitiesController],
  providers: [VulnerabilitiesService, VulnerabilityWorkflowValidator],
  exports: [VulnerabilitiesService],
})
export class VulnerabilitiesModule {}

