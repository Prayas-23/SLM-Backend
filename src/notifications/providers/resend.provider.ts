import { Injectable, Logger } from '@nestjs/common';
import { IEmailProvider, EmailPayload } from './email.provider.interface';

// ── HTTP timeout (ms) ─────────────────────────────────────────────────────────
const REQUEST_TIMEOUT_MS = 12_000; // 12 seconds

// ── Retry configuration ───────────────────────────────────────────────────────
const MAX_ATTEMPTS = 3;
const BASE_BACKOFF_MS = 1_000; // 1s → 2s → 4s (capped at 3 attempts)

/**
 * HTTP status codes that indicate a permanent, non-retryable failure.
 * These are API-layer rejections (bad request, auth) — retrying won't help.
 */
const PERMANENT_FAILURE_CODES = new Set([400, 401, 403, 422]);

@Injectable()
export class ResendProvider implements IEmailProvider {
  private apiKey: string = '';
  private senderEmail: string = '';
  private senderName: string = '';
  private readonly logger = new Logger(ResendProvider.name);

  initialize(config: Record<string, string>): void {
    this.apiKey = config['apiKey'] || '';
    this.senderEmail = config['senderEmail'] || 'notifications@sentinel-slm.com';
    this.senderName = config['senderName'] || 'Sentinel SLM';
  }

  async sendEmail(payload: EmailPayload): Promise<void> {
    if (!this.apiKey) {
      this.logger.warn('Resend API key is missing. Skipping email delivery.');
      return;
    }

    const fromString = `${this.senderName} <${this.senderEmail}>`;
    const toArray = Array.isArray(payload.to) ? payload.to : [payload.to];
    const requestBody = JSON.stringify({
      from: fromString,
      to: toArray,
      subject: payload.subject,
      html: payload.html,
    });

    await this.sendWithRetry(toArray, requestBody);
  }

  // ── Core HTTP dispatch with timeout ────────────────────────────────────────

  private async dispatchOnce(requestBody: string): Promise<void> {
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

    let response: Response;
    try {
      response = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${this.apiKey}`,
        },
        body: requestBody,
        signal: controller.signal,
      });
    } catch (err) {
      // fetch() only throws for network errors or AbortError
      if (err instanceof Error && err.name === 'AbortError') {
        throw new ProviderTimeoutError(
          `Resend request timed out after ${REQUEST_TIMEOUT_MS / 1000}s`,
        );
      }
      throw err; // Re-throw genuine network errors — these are retriable
    } finally {
      clearTimeout(timeoutHandle);
    }

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      const message = `Resend API Error (${response.status}): ${body}`;

      // Permanent failures must not be retried
      if (PERMANENT_FAILURE_CODES.has(response.status)) {
        throw new PermanentProviderError(message, response.status);
      }

      // Temporary failures (5xx, 429, etc.) are retriable
      throw new TemporaryProviderError(message, response.status);
    }
  }

  // ── Retry with exponential backoff ─────────────────────────────────────────

  private async sendWithRetry(toArray: string[], requestBody: string): Promise<void> {
    let lastError: unknown;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        await this.dispatchOnce(requestBody);
        this.logger.log(`Email sent successfully to ${toArray.join(', ')} (attempt ${attempt})`);
        return; // success — exit immediately
      } catch (err) {
        lastError = err;

        // Permanent errors must not be retried
        if (err instanceof PermanentProviderError) {
          this.logger.error(
            `Permanent delivery failure to ${toArray.join(', ')}: ${err.message}`,
          );
          throw err;
        }

        if (attempt < MAX_ATTEMPTS) {
          const backoffMs = BASE_BACKOFF_MS * Math.pow(2, attempt - 1);
          this.logger.warn(
            `Email delivery attempt ${attempt}/${MAX_ATTEMPTS} failed for ${toArray.join(', ')}. ` +
            `Retrying in ${backoffMs}ms. Reason: ${err instanceof Error ? err.message : String(err)}`,
          );
          await sleep(backoffMs);
        } else {
          this.logger.error(
            `All ${MAX_ATTEMPTS} delivery attempts exhausted for ${toArray.join(', ')}: ` +
            `${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }

    throw lastError;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Thrown when the HTTP request exceeds the configured timeout. Retriable. */
class ProviderTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProviderTimeoutError';
  }
}

/**
 * Thrown for permanent API rejections (400, 401, 403, 422).
 * These must NOT be retried — the request itself is invalid.
 */
export class PermanentProviderError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'PermanentProviderError';
  }
}

/**
 * Thrown for temporary transport failures (5xx, 429, network errors).
 * These will be retried up to MAX_ATTEMPTS.
 */
class TemporaryProviderError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'TemporaryProviderError';
  }
}
