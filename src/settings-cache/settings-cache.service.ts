import { Injectable, OnModuleInit, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class SettingsCacheService implements OnModuleInit {
  private readonly logger = new Logger(SettingsCacheService.name);
  private cache: Record<string, string> = {};

  constructor(private readonly prisma: PrismaService) {}

  async onModuleInit() {
    await this.refresh();
  }

  async refresh() {
    const settings = await this.prisma.platformSetting.findMany();
    const newCache: Record<string, string> = {};
    for (const setting of settings) {
      newCache[setting.key] = setting.value;
    }
    this.cache = newCache;
    this.logger.log('Platform settings cache loaded into memory.');
  }

  get(key: string, defaultValue?: string): string {
    return this.cache[key] ?? defaultValue ?? '';
  }

  getNumber(key: string, defaultValue: number): number {
    const val = this.cache[key];
    if (val === undefined || val === null) return defaultValue;
    const parsed = parseInt(val, 10);
    return isNaN(parsed) ? defaultValue : parsed;
  }
}
