import { Injectable } from '@nestjs/common';
import type { IAIProvider, AIConfig } from './ai-provider.interface';
import { GeminiProvider } from './gemini.provider';
import { OpenRouterProvider } from './openrouter.provider';

/**
 * AIProviderFactory
 *
 * The single point of LLM provider resolution for the entire platform.
 * AIService must NEVER instantiate providers directly.
 *
 * To add a new provider in the future:
 *   1. Create a class that implements IAIProvider.
 *   2. Add a new `case` block below.
 *   3. No other file needs to change.
 *
 * Supported providers:
 *   GEMINI   — Google Gemini (current default)
 *
 * Future providers (add a case when ready):
 *   OPENAI   — OpenAI GPT-4o, GPT-4-turbo
 *   CLAUDE   — Anthropic Claude 3.5
 *   AZURE    — Azure OpenAI Service
 *   OLLAMA   — Self-hosted Ollama
 *   LLAMA    — Meta Llama (via any compatible API)
 */
@Injectable()
export class AIProviderFactory {
  /**
   * Returns an initialized IAIProvider for the given provider type.
   *
   * @param config  Full AI configuration loaded from PlatformSetting.
   */
  create(config: AIConfig): IAIProvider {
    let provider: IAIProvider;

    switch (config.provider.toUpperCase()) {
      case 'GEMINI':
        provider = new GeminiProvider();
        break;

      case 'OPENROUTER':
        provider = new OpenRouterProvider();
        break;

      // ── Future providers — add cases here without modifying AIService ──
      // case 'OPENAI':
      //   provider = new OpenAIProvider();
      //   break;
      // case 'CLAUDE':
      //   provider = new ClaudeProvider();
      //   break;
      // case 'AZURE':
      //   provider = new AzureOpenAIProvider();
      //   break;
      // case 'OLLAMA':
      //   provider = new OllamaProvider();
      //   break;

      default:
        // Unknown provider — fall back to Gemini with a warning.
        // This prevents a hard crash if an unsupported key is stored in DB.
        provider = new GeminiProvider();
        break;
    }

    provider.initialize(config);
    return provider;
  }
}
