import { Module } from '@nestjs/common';
import { CloudAccountsService } from './cloud-accounts.service';
import { CloudAccountsController } from './cloud-accounts.controller';

@Module({
  controllers: [CloudAccountsController],
  providers: [CloudAccountsService],
  exports: [CloudAccountsService],
})
export class CloudAccountsModule {}
