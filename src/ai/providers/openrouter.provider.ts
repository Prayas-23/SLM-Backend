import { Logger } from '@nestjs/common';
import OpenAI from 'openai';
import type {
  IAIProvider,
  AIConfig,
  AIMessage,
  AIResponse,
  AIHealthStatus,
} from './ai-provider.interface';
import {
  OpenRouterTimeoutError,
  OpenRouterPermanentError,
  OpenRouterTemporaryError,
} from './openrouter.errors';

// ── Retry configuration ───────────────────────────────────────────────────────
const MAX_ATTEMPTS   = 3;
const BASE_BACKOFF_MS = 1_000; // 1 s → 2 s → 4 s (exponential, capped at 3 attempts)

/** HTTP status codes that are permanent (auth / bad request). Do not retry. */
const PERMANENT_CODES = new Set([400, 401, 403, 422]);

/**
 * OpenRouterProvider
 *
 * OpenAI-compatible HTTP implementation of IAIProvider for OpenRouter.
 * Uses the official 'openai' npm package.
 *
 * Features:
 *   - Configurable model, temperature, maxTokens, timeout
 *   - Exponential backoff retry (up to MAX_ATTEMPTS)
 *   - Permanent vs temporary error classification
 *   - healthCheck() via a minimal "ping" prompt
 */
export class OpenRouterProvider implements IAIProvider {
  private readonly logger = new Logger(OpenRouterProvider.name);

  private client:      OpenAI | null = null;
  private apiKey:      string  = '';
  private model:       string  = 'openai/gpt-4o';
  private temperature: number  = 0.2;
  private maxTokens:   number  = 1024;
  private timeoutMs:   number  = 30_000;

  // ── IAIProvider: initialize ─────────────────────────────────────────────────

  initialize(config: AIConfig): void {
    this.apiKey      = config.apiKey;
    this.model       = config.model       || 'openai/gpt-4o';
    this.temperature = config.temperature ?? 0.2;
    this.maxTokens   = config.maxTokens   || 1024;
    this.timeoutMs   = config.timeoutMs   || 30_000;

    if (this.apiKey) {
      this.client = new OpenAI({
        baseURL: 'https://openrouter.ai/api/v1',
        apiKey: this.apiKey,
        timeout: this.timeoutMs,
        maxRetries: 0, // Disable SDK internal retries to use our exact exponential backoff logic
      });
    }
  }

  // ── IAIProvider: generateResponse ───────────────────────────────────────────

  async generateResponse(messages: AIMessage[]): Promise<AIResponse> {
    if (!this.apiKey || !this.client) {
      throw new OpenRouterPermanentError('OpenRouter API key is not configured.', 401);
    }

    const startedAt = Date.now();
    const responseBody = await this.postWithRetry(messages);
    const latencyMs = Date.now() - startedAt;

    const text = responseBody.choices?.[0]?.message?.content ?? '';
    const usage = responseBody.usage;

    return {
      text,
      provider:          'OPENROUTER',
      model:             this.model,
      promptTokens:      usage?.prompt_tokens,
      completionTokens:  usage?.completion_tokens,
      totalTokens:       usage?.total_tokens,
      latencyMs,
    };
  }

  // ── IAIProvider: healthCheck ─────────────────────────────────────────────────

  async healthCheck(): Promise<AIHealthStatus> {
    if (!this.apiKey || !this.client) {
      return { provider: 'OPENROUTER', model: this.model, enabled: false, reachable: false, error: 'API key not configured.' };
    }

    const start = Date.now();
    try {
      await this.dispatchOnce([{ role: 'user', content: 'ping' }]);
      return { provider: 'OPENROUTER', model: this.model, enabled: true, reachable: true, latencyMs: Date.now() - start };
    } catch (err) {
      return {
        provider:  'OPENROUTER',
        model:     this.model,
        enabled:   true,
        reachable: false,
        latencyMs: Date.now() - start,
        error:     err instanceof Error ? err.message : String(err),
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async dispatchOnce(messages: AIMessage[]): Promise<OpenAI.Chat.Completions.ChatCompletion> {
    if (!this.client) {
      throw new OpenRouterPermanentError('OpenRouter client is not initialized.', 401);
    }

    try {
      const response = await this.client.chat.completions.create({
        model: this.model,
        messages: messages.map((m) => ({
          role: m.role,
          content: m.content,
        })),
        temperature: this.temperature,
        max_tokens: this.maxTokens,
      });
      return response;
    } catch (err: any) {
      if (err instanceof OpenAI.APIConnectionTimeoutError) {
        throw new OpenRouterTimeoutError(`OpenRouter request timed out after ${this.timeoutMs / 1000}s`);
      }
      
      if (err instanceof OpenAI.APIError) {
        const status = err.status || 500;
        const message = `OpenRouter API Error (${status}): ${err.message}`;
        
        if (PERMANENT_CODES.has(status)) {
          throw new OpenRouterPermanentError(message, status);
        }
        throw new OpenRouterTemporaryError(message, status);
      }
      
      throw err;
    }
  }

  private async postWithRetry(messages: AIMessage[]): Promise<OpenAI.Chat.Completions.ChatCompletion> {
    let lastError: unknown;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        const result = await this.dispatchOnce(messages);
        this.logger.log(`OpenRouter request succeeded (attempt ${attempt})`);
        return result;
      } catch (err) {
        lastError = err;

        if (err instanceof OpenRouterPermanentError) {
          this.logger.error(`OpenRouter permanent failure: ${err.message}`);
          throw err;
        }

        if (attempt < MAX_ATTEMPTS) {
          const backoffMs = BASE_BACKOFF_MS * Math.pow(2, attempt - 1);
          this.logger.warn(
            `OpenRouter attempt ${attempt}/${MAX_ATTEMPTS} failed. Retrying in ${backoffMs}ms. ` +
            `Reason: ${err instanceof Error ? err.message : String(err)}`,
          );
          await sleep(backoffMs);
        } else {
          this.logger.error(
            `All ${MAX_ATTEMPTS} OpenRouter attempts exhausted: ` +
            `${err instanceof Error ? err.message : String(err)}`,
          );
        }
      }
    }

    throw lastError;
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
