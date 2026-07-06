import { Module, Global } from '@nestjs/common';
import { SettingsCacheService } from './settings-cache.service';
import { PrismaModule } from '../prisma/prisma.module';

@Global()
@Module({
  imports: [PrismaModule],
  providers: [SettingsCacheService],
  exports: [SettingsCacheService],
})
export class SettingsCacheModule {}
