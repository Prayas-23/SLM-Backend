import { Module } from '@nestjs/common';
import { NotificationsService } from './notifications.service';
import { NotificationsController } from './notifications.controller';
import { NotificationProviderFactory } from './providers/notification-provider.factory';

@Module({
  controllers: [NotificationsController],
  providers: [
    NotificationProviderFactory,
    NotificationsService,
  ],
  exports: [NotificationsService],
})
export class NotificationsModule {}
