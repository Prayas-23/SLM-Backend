import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

/**
 * Sentinel SLM — Global HTTP Exception Filter
 *
 * Catches all HttpExceptions and returns a standardized error response.
 *
 * Response shape:
 * {
 *   success: false,
 *   statusCode: number,
 *   message: string,
 *   errors: any | null,
 *   timestamp: string,
 *   path: string
 * }
 */
@Catch(HttpException)
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: HttpException, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = exception instanceof HttpException
      ? exception.getStatus()
      : HttpStatus.INTERNAL_SERVER_ERROR;

    const exceptionResponse = exception.getResponse();

    let message: string;
    let errors: unknown = null;

    if (typeof exceptionResponse === 'string') {
      message = exceptionResponse;
    } else if (typeof exceptionResponse === 'object' && exceptionResponse !== null) {
      const resp = exceptionResponse as Record<string, unknown>;
      message = (resp.message as string) || exception.message;
      // Class-validator sends an array of validation errors
      if (Array.isArray(resp.message)) {
        message = 'Validation failed';
        errors = resp.message;
      }
    } else {
      message = exception.message;
    }

    const errorBody = {
      success: false,
      statusCode: status,
      message,
      errors,
      timestamp: new Date().toISOString(),
      path: request.url,
    };

    this.logger.warn(
      `[${request.method}] ${request.url} → ${status}: ${message}`,
    );

    response.status(status).json(errorBody);
  }
}

/**
 * Catches ALL unhandled errors (including non-HTTP errors like DB errors).
 * Returns a generic 500 response without leaking internals.
 */
@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request = ctx.getRequest<Request>();

    const status = HttpStatus.INTERNAL_SERVER_ERROR;

    this.logger.error(
      `Unhandled exception on [${request.method}] ${request.url}`,
      exception instanceof Error ? exception.stack : String(exception),
    );

    response.status(status).json({
      success: false,
      statusCode: status,
      message: 'Internal server error',
      errors: null,
      timestamp: new Date().toISOString(),
      path: request.url,
    });
  }
}
