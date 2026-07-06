import { Injectable, NestInterceptor, ExecutionContext, CallHandler, PayloadTooLargeException } from '@nestjs/common';
import { SettingsCacheService } from '../../settings-cache/settings-cache.service';

@Injectable()
export class UploadLimitInterceptor implements NestInterceptor {
  constructor(private readonly settingsCache: SettingsCacheService) {}

  async intercept(context: ExecutionContext, next: CallHandler) {
    const maxMb = this.settingsCache.getNumber('security.maxUploadSizeMb', 20);
    const maxBytes = maxMb * 1024 * 1024;

    const request = context.switchToHttp().getRequest();
    const file = request.file;

    if (file && file.size > maxBytes) {
      throw new PayloadTooLargeException(`File size exceeds the limit of ${maxMb} MB`);
    }

    return next.handle();
  }
}
