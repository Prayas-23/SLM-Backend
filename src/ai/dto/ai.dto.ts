import { IsString, IsNotEmpty, IsOptional, MaxLength, MinLength } from 'class-validator';
import type { AIHealthStatus, AIResponse } from '../providers/ai-provider.interface';

// ── Request DTOs ──────────────────────────────────────────────────────────────

export class TestAIConnectionDto {
  @IsString()
  @IsNotEmpty()
  @IsOptional()
  @MaxLength(500)
  /** Optional prompt override. Defaults to a simple connectivity ping. */
  prompt?: string;
}

export class DetectIntentDto {
  @IsString()
  @MinLength(1)
  @MaxLength(1000)
  query: string;

  /** Optional: attach this query to an existing conversation session. */
  @IsOptional()
  @IsString()
  conversationId?: string;
}

// ── Response shapes ───────────────────────────────────────────────────────────

export interface AIHealthResponse extends AIHealthStatus {}

export interface AITestResponse {
  success:   boolean;
  response?: AIResponse;
  error?:    string;
  auditId?:  string;
}

export interface AISettingsResponse {
  enabled:     boolean;
  provider:    string;
  model:       string;
  temperature: number;
  maxTokens:   number;
  /** API key is masked — never the raw value */
  apiKeyMasked: string;
}
