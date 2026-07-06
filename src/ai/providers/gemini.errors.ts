// ── Gemini Provider Exceptions ────────────────────────────────────────────────

/** Thrown when the HTTP request exceeds the configured timeout. Retriable. */
export class GeminiTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GeminiTimeoutError';
  }
}

/**
 * Thrown for permanent API rejections (400, 401, 403, 429-auth, 422).
 * These must NOT be retried — the request itself is invalid or unauthorized.
 */
export class GeminiPermanentError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'GeminiPermanentError';
  }
}

/**
 * Thrown for temporary transport failures (5xx, network errors).
 * These will be retried up to MAX_ATTEMPTS.
 */
export class GeminiTemporaryError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'GeminiTemporaryError';
  }
}
