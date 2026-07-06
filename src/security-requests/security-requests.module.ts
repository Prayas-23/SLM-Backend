import { Module } from '@nestjs/common';
import { MulterModule } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { SecurityRequestsService } from './security-requests.service';
import { SecurityRequestsController } from './security-requests.controller';
import { RequestWorkflowValidator } from './workflow/request-workflow.validator';

@Module({
  imports: [
    MulterModule.register({ storage: memoryStorage() }),
  ],
  controllers: [SecurityRequestsController],
  providers: [SecurityRequestsService, RequestWorkflowValidator],
  exports: [SecurityRequestsService],
})
export class SecurityRequestsModule {}
