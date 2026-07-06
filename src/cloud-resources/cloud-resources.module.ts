import { Module } from '@nestjs/common';
import { CloudResourcesService } from './cloud-resources.service';
import { CloudResourcesController } from './cloud-resources.controller';

@Module({
  controllers: [CloudResourcesController],
  providers: [CloudResourcesService],
  exports: [CloudResourcesService],
})
export class CloudResourcesModule {}
