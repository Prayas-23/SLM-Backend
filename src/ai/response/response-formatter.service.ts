import { Injectable } from '@nestjs/common';
import { AIResponseDto } from './ai-response.dto';
import type { AIResponse } from '../providers/ai-provider.interface';

/**
 * ResponseFormatterService
 *
 * Standardizes every AI response before it leaves the AI layer.
 *
 * Responsibilities:
 *   - Clean raw Gemini output (strip excess whitespace, normalize bullets)
 *   - Attach token usage metadata
 *   - Attach suggestions
 *   - Enforce the AIResponseDto contract
 *
 * The formatter — not Gemini — controls the final shape.
 */
@Injectable()
export class ResponseFormatterService {

  /**
   * Assembles the final AIResponseDto from a raw provider response and suggestions.
   */
  format(
    rawResponse: AIResponse,
    suggestions: string[],
  ): AIResponseDto {
    return {
      answer:      this.cleanText(rawResponse.text),
      suggestions,
      metadata: {
        provider:         rawResponse.provider,
        model:            rawResponse.model,
        responseTimeMs:   rawResponse.latencyMs,
        promptTokens:     rawResponse.promptTokens,
        completionTokens: rawResponse.completionTokens,
        totalTokens:      rawResponse.totalTokens,
      },
    };
  }

  /**
   * Returns a standardized error response when AI generation fails.
   * Never exposes internal provider exceptions.
   */
  formatError(reason: string): AIResponseDto {
    return {
      answer:      this.getUserFacingError(reason),
      suggestions: ['What can Sentinel AI do?', 'Show critical vulnerabilities', 'Help'],
      metadata: {
        provider:       'UNAVAILABLE',
        model:          'UNAVAILABLE',
        responseTimeMs: 0,
      },
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Normalizes Gemini text output:
   *   - Collapses multiple blank lines into one
   *   - Normalizes bullet characters (• → -)
   *   - Trims leading/trailing whitespace
   */
  private cleanText(raw: string): string {
    return raw
      .replace(/•/g, '-')
      .replace(/\n{3,}/g, '\n\n')
      .replace(/[ \t]+$/gm, '')
      .trim();
  }

  /**
   * Maps internal error patterns to user-facing messages.
   * Never leaks provider exception details.
   */
  private getUserFacingError(reason: string): string {
    const lower = reason.toLowerCase();

    if (lower.includes('disabled'))   return 'AI features are currently disabled. Please contact your Security Lead to enable them in Settings.';
    if (lower.includes('timeout'))    return 'The AI provider took too long to respond. Please try again in a moment.';
    if (lower.includes('429'))        return 'AI request limit reached. Please wait a few seconds and try again.';
    if (lower.includes('401') || lower.includes('403')) return 'AI provider authentication failed. Please check the API key in Settings → AI Configuration.';
    if (lower.includes('token'))      return 'Your query returned too much data for the AI to process. Try narrowing your filters.';
    if (lower.includes('unknown'))    return 'I wasn\'t able to understand that request. Please rephrase your question or type "Help" to see what I can do.';

    return 'I was unable to generate a response. Please try again or rephrase your question.';
  }
}
