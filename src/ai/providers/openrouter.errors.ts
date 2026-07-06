// ── OpenRouter Provider Exceptions ────────────────────────────────────────────

/** Thrown when the HTTP request exceeds the configured timeout. Retriable. */
export class OpenRouterTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'OpenRouterTimeoutError';
  }
}

/**
 * Thrown for permanent API rejections (400, 401, 403, 429-auth, 422).
 * These must NOT be retried — the request itself is invalid or unauthorized.
 */
export class OpenRouterPermanentError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'OpenRouterPermanentError';
  }
}

/**
 * Thrown for temporary transport failures (5xx, network errors).
 * These will be retried up to MAX_ATTEMPTS.
 */
export class OpenRouterTemporaryError extends Error {
  constructor(message: string, public readonly statusCode: number) {
    super(message);
    this.name = 'OpenRouterTemporaryError';
  }
}
