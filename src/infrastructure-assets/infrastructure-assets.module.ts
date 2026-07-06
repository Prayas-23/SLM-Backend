import { Module } from '@nestjs/common';
import { InfrastructureAssetsService } from './infrastructure-assets.service';
import { InfrastructureAssetsController } from './infrastructure-assets.controller';

@Module({
  controllers: [InfrastructureAssetsController],
  providers: [InfrastructureAssetsService],
  exports: [InfrastructureAssetsService],
})
export class InfrastructureAssetsModule {}
