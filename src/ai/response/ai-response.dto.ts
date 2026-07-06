/**
 * AIResponseDto — the standard response for every AI feature in Sentinel SLM.
 *
 * Produced by ResponseFormatterService after Gemini generates the answer.
 * This DTO is the only shape the frontend should ever receive from the AI layer.
 *
 * Phase 3+ (conversation history, RAG, agents) will extend this DTO,
 * not replace it, to maintain backward compatibility.
 */
export interface AIResponseDto {
  /** The natural language answer from Gemini — never SQL, never JSON. */
  answer: string;

  /** Contextual follow-up suggestions from SuggestionService. */
  suggestions: string[];

  /** Provenance and billing metadata. */
  metadata: {
    provider:         string;
    model:            string;
    responseTimeMs:   number;
    promptTokens?:    number;
    completionTokens?: number;
    totalTokens?:     number;
  };
}

/**
 * AISearchResponseDto — full pipeline response from POST /ai/search.
 * Wraps the AIResponseDto with the pipeline context for observability.
 */
export interface AISearchResponseDto {
  success:  boolean;
  response: AIResponseDto;
  pipeline: {
    entity:       string;
    operation:    string;
    confidence:   number;
    resultCount:  number;
    filtersApplied: Record<string, string | undefined>;
  };
  error?: string;
}
