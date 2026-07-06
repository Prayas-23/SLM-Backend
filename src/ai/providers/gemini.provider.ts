import { Logger } from '@nestjs/common';
import type {
  IAIProvider,
  AIConfig,
  AIMessage,
  AIResponse,
  AIHealthStatus,
} from './ai-provider.interface';
import {
  GeminiTimeoutError,
  GeminiPermanentError,
  GeminiTemporaryError,
} from './gemini.errors';

// ── Retry configuration ───────────────────────────────────────────────────────
const MAX_ATTEMPTS   = 3;
const BASE_BACKOFF_MS = 1_000; // 1 s → 2 s → 4 s (exponential, capped at 3 attempts)

/** HTTP status codes that are permanent (auth / bad request). Do not retry. */
const PERMANENT_CODES = new Set([400, 401, 403, 422]);

// ── Gemini REST API base ──────────────────────────────────────────────────────
const GEMINI_BASE = 'https://generativelanguage.googleapis.com/v1beta/models';

// ── Gemini REST shape helpers ─────────────────────────────────────────────────
interface GeminiPart    { text: string }
interface GeminiContent { role: string; parts: GeminiPart[] }
interface GeminiRequest {
  contents:            GeminiContent[];
  systemInstruction?:  { parts: GeminiPart[] };
  generationConfig:    { temperature: number; maxOutputTokens: number };
}
interface GeminiCandidate { content: { parts: GeminiPart[] } }
interface GeminiResponse  {
  candidates:    GeminiCandidate[];
  usageMetadata: {
    promptTokenCount:     number;
    candidatesTokenCount: number;
    totalTokenCount:      number;
  };
}

/**
 * GeminiProvider
 *
 * Native HTTP implementation of IAIProvider for Google Gemini.
 * Uses the generateContent REST API endpoint — no SDK dependency.
 *
 * Features:
 *   - Configurable model, temperature, maxTokens, timeout
 *   - Exponential backoff retry (up to MAX_ATTEMPTS)
 *   - Permanent vs temporary error classification
 *   - System instruction forwarded as Gemini systemInstruction field
 *   - healthCheck() via a minimal "ping" prompt
 */
export class GeminiProvider implements IAIProvider {
  private readonly logger = new Logger(GeminiProvider.name);

  private apiKey:      string  = '';
  private model:       string  = 'gemini-2.0-flash';
  private temperature: number  = 0.2;
  private maxTokens:   number  = 1024;
  private timeoutMs:   number  = 30_000;

  // ── IAIProvider: initialize ─────────────────────────────────────────────────

  initialize(config: AIConfig): void {
    this.apiKey      = config.apiKey;
    this.model       = config.model       || 'gemini-2.0-flash';
    this.temperature = config.temperature ?? 0.2;
    this.maxTokens   = config.maxTokens   || 1024;
    this.timeoutMs   = config.timeoutMs   || 30_000;
  }

  // ── IAIProvider: generateResponse ───────────────────────────────────────────

  async generateResponse(messages: AIMessage[]): Promise<AIResponse> {
    if (!this.apiKey) {
      throw new GeminiPermanentError('Gemini API key is not configured.', 401);
    }

    const startedAt = Date.now();
    const { systemText, conversationContents } = this.splitMessages(messages);
    const requestBody = this.buildRequest(systemText, conversationContents);
    const responseBody = await this.postWithRetry(requestBody);
    const latencyMs = Date.now() - startedAt;

    const text = responseBody.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
    const usage = responseBody.usageMetadata;

    return {
      text,
      provider:          'GEMINI',
      model:             this.model,
      promptTokens:      usage?.promptTokenCount,
      completionTokens:  usage?.candidatesTokenCount,
      totalTokens:       usage?.totalTokenCount,
      latencyMs,
    };
  }

  // ── IAIProvider: healthCheck ─────────────────────────────────────────────────

  async healthCheck(): Promise<AIHealthStatus> {
    if (!this.apiKey) {
      return { provider: 'GEMINI', model: this.model, enabled: false, reachable: false, error: 'API key not configured.' };
    }

    const start = Date.now();
    try {
      const body = this.buildRequest(null, [{ role: 'user', parts: [{ text: 'ping' }] }]);
      await this.dispatchOnce(JSON.stringify(body));
      return { provider: 'GEMINI', model: this.model, enabled: true, reachable: true, latencyMs: Date.now() - start };
    } catch (err) {
      return {
        provider:  'GEMINI',
        model:     this.model,
        enabled:   true,
        reachable: false,
        latencyMs: Date.now() - start,
        error:     err instanceof Error ? err.message : String(err),
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private splitMessages(messages: AIMessage[]): {
    systemText: string | null;
    conversationContents: GeminiContent[];
  } {
    const systemMessages = messages.filter((m) => m.role === 'system');
    const otherMessages  = messages.filter((m) => m.role !== 'system');

    const systemText = systemMessages.length > 0
      ? systemMessages.map((m) => m.content).join('\n\n')
      : null;

    const conversationContents: GeminiContent[] = otherMessages.map((m) => ({
      // Gemini uses 'model' for the assistant turn
      role:  m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.content }],
    }));

    return { systemText, conversationContents };
  }

  private buildRequest(
    systemText: string | null,
    contents: GeminiContent[],
  ): GeminiRequest {
    const body: GeminiRequest = {
      contents,
      generationConfig: {
        temperature:      this.temperature,
        maxOutputTokens:  this.maxTokens,
      },
    };
    if (systemText) {
      body.systemInstruction = { parts: [{ text: systemText }] };
    }
    return body;
  }

  private async dispatchOnce(requestBody: string): Promise<GeminiResponse> {
    const url = `${GEMINI_BASE}/${this.model}:generateContent?key=${this.apiKey}`;
    const controller = new AbortController();
    const timeoutHandle = setTimeout(() => controller.abort(), this.timeoutMs);

    let response: Response;
    try {
      response = await fetch(url, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    requestBody,
        signal:  controller.signal,
      });
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        throw new GeminiTimeoutError(`Gemini request timed out after ${this.timeoutMs / 1000}s`);
      }
      throw err;
    } finally {
      clearTimeout(timeoutHandle);
    }

    if (!response.ok) {
      const body    = await response.text().catch(() => '');
      const message = `Gemini API Error (${response.status}): ${body}`;
      if (PERMANENT_CODES.has(response.status)) {
        throw new GeminiPermanentError(message, response.status);
      }
      throw new GeminiTemporaryError(message, response.status);
    }

    return response.json() as Promise<GeminiResponse>;
  }

  private async postWithRetry(requestBody: GeminiRequest): Promise<GeminiResponse> {
    const serialized = JSON.stringify(requestBody);
    let lastError: unknown;

    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        const result = await this.dispatchOnce(serialized);
        this.logger.log(`Gemini request succeeded (attempt ${attempt})`);
        return result;
      } catch (err) {
        lastError = err;

        if (err instanceof GeminiPermanentError) {
          this.logger.error(`Gemini permanent failure: ${err.message}`);
          throw err;
        }

        if (attempt < MAX_ATTEMPTS) {
          const backoffMs = BASE_BACKOFF_MS * Math.pow(2, attempt - 1);
          this.logger.warn(
            `Gemini attempt ${attempt}/${MAX_ATTEMPTS} failed. Retrying in ${backoffMs}ms. ` +
            `Reason: ${err instanceof Error ? err.message : String(err)}`,
          );
          await sleep(backoffMs);
        } else {
          this.logger.error(
            `All ${MAX_ATTEMPTS} Gemini attempts exhausted: ` +
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
