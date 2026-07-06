import { ConfigService } from '@nestjs/config';
import * as winston from 'winston';
import 'winston-daily-rotate-file';

/**
 * Sentinel SLM — Winston Logger Factory
 *
 * Creates a winston logger instance with:
 *   - Colorized console output (dev)
 *   - Rotating daily log files (all levels)
 *   - Dedicated rotating error log file
 */
export function createWinstonOptions(configService?: ConfigService) {
  const logLevel = configService?.get<string>('logging.level') ?? process.env.LOG_LEVEL ?? 'debug';
  const logDir   = configService?.get<string>('logging.dir')   ?? process.env.LOG_DIR   ?? 'logs';
  const isProduction = (process.env.NODE_ENV || 'development') === 'production';

  const consoleFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.ms(),
    winston.format.colorize({ all: true }),
    winston.format.printf(({ timestamp, level, message, context, ms }) => {
      return `[${timestamp}] ${level} [${context ?? 'App'}] ${message} ${ms}`;
    }),
  );

  const fileFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
  );

  const transports: winston.transport[] = [
    // ── Console ──────────────────────────────────────────────────────────────
    new winston.transports.Console({
      level: isProduction ? 'info' : logLevel,
      format: isProduction ? fileFormat : consoleFormat,
    }),

    // ── Daily Rotating File (all levels) ─────────────────────────────────────
    new (winston.transports as unknown as { DailyRotateFile: new (opts: unknown) => any }).DailyRotateFile({
      dirname: logDir,
      filename: 'sentinel-slm-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      level: logLevel,
      format: fileFormat,
    }),

    // ── Error-only log ────────────────────────────────────────────────────────
    new (winston.transports as unknown as { DailyRotateFile: new (opts: unknown) => any }).DailyRotateFile({
      dirname: logDir,
      filename: 'sentinel-slm-error-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '90d',
      level: 'error',
      format: fileFormat,
    }),
  ];

  return {
    transports,
  };
}
