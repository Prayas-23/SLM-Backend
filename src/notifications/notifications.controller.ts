import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { NotificationsService } from './notifications.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '@prisma/client';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('notifications')
export class NotificationsController {
  constructor(private readonly service: NotificationsService) {}

  @Post('test')
  @Roles(UserRole.SECURITY_LEAD)
  async testConnection(@Body() body: { recipient: string }) {
    await this.service.sendTestEmail(body.recipient);
    return { message: 'Test email dispatched. Check audit logs for status.' };
  }
}
