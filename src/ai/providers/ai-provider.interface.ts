// ── AI Provider Interface ─────────────────────────────────────────────────────
//
// All LLM providers must implement this interface.
// AIService only speaks to IAIProvider — never to concrete providers directly.
//
// Future providers (OpenAI, Claude, Azure OpenAI, Ollama, Llama, etc.)
// must implement this interface and register one factory case.
// No other files need to change.

export interface AIConfig {
  /** Provider type key e.g. GEMINI | OPENAI | CLAUDE | AZURE | OLLAMA */
  provider:    string;
  /** Raw API key — never logged, never returned to frontend */
  apiKey:      string;
  /** Model identifier e.g. gemini-2.0-flash, gpt-4o, claude-3-5-sonnet */
  model:       string;
  /** Sampling temperature (0.0 – 1.0) */
  temperature: number;
  /** Maximum output tokens */
  maxTokens:   number;
  /** HTTP request timeout in milliseconds */
  timeoutMs:   number;
}

export interface AIMessage {
  role:    'system' | 'user' | 'assistant';
  content: string;
}

export interface AIResponse {
  /** Raw text output from the model */
  text:              string;
  /** Provider name that produced this response */
  provider:          string;
  /** Model that produced this response */
  model:             string;
  /** Approximate token usage (provider-specific, best-effort) */
  promptTokens?:     number;
  completionTokens?: number;
  totalTokens?:      number;
  /** Wall-clock latency in milliseconds */
  latencyMs:         number;
}

export interface AIHealthStatus {
  provider:   string;
  model:      string;
  enabled:    boolean;
  reachable:  boolean;
  latencyMs?: number;
  error?:     string;
}

/**
 * IAIProvider — the only contract AIService uses when communicating with LLMs.
 *
 * Implementing classes must:
 *   1. Accept configuration via initialize().
 *   2. Generate text responses via generateResponse().
 *   3. Report connectivity via healthCheck().
 *
 * No business logic should exist inside providers.
 * They only translate between the interface and their provider's HTTP API.
 */
export interface IAIProvider {
  /**
   * Applies configuration (API key, model, temperature, etc.).
   * Called by AIProviderFactory after construction, and on every refreshConfig().
   */
  initialize(config: AIConfig): void;

  /**
   * Sends a message array to the LLM and returns the response.
   * Implementations must apply timeout and retry logic internally.
   */
  generateResponse(messages: AIMessage[]): Promise<AIResponse>;

  /**
   * Verifies that the provider endpoint is reachable and the API key is valid.
   * Must never throw — always resolve with a status object.
   */
  healthCheck(): Promise<AIHealthStatus>;
}
