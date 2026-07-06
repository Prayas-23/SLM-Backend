import { ConfigService } from '@nestjs/config';

/**
 * Sentinel SLM — Redis Configuration
 *
 * Returns an ioredis-compatible connection options object.
 * Used by BullMQ and any future cache/pub-sub integrations.
 */
export function getRedisConfig(configService: ConfigService) {
  return {
    host: configService.get<string>('redis.host', 'localhost'),
    port: configService.get<number>('redis.port', 6379),
    password: configService.get<string | undefined>('redis.password') || undefined,
    // Reconnect strategy: exponential backoff up to 30 seconds
    retryStrategy: (times: number) => Math.min(times * 500, 30_000),
    maxRetriesPerRequest: null, // required by BullMQ
    enableReadyCheck: false,    // required by BullMQ
  };
}

/**
 * Redis connection configuration string (for modules that accept a URL).
 */
export function getRedisUrl(configService: ConfigService): string {
  const host = configService.get<string>('redis.host', 'localhost');
  const port = configService.get<number>('redis.port', 6379);
  const password = configService.get<string | undefined>('redis.password');
  return password
    ? `redis://:${password}@${host}:${port}`
    : `redis://${host}:${port}`;
}
