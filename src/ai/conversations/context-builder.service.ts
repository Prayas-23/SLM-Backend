import { Injectable, Logger } from '@nestjs/common';
import { ConversationRepository } from './conversation.repository';

/** One turn = one user message + one assistant reply */
const MAX_CONTEXT_TURNS = 6; // configurable — keep last 6 exchanges
const MAX_CONTEXT_CHARS = 4000; // hard cap on context size for token safety

export interface ContextMessage {
  role: 'USER' | 'ASSISTANT';
  content: string;
}

/**
 * ContextBuilderService
 *
 * Loads recent conversation history and formats it for the PromptBuilder.
 *
 * Design goals:
 *   - Never send the entire conversation to Gemini (token cost + latency)
 *   - Always cap context at MAX_CONTEXT_TURNS exchanges
 *   - Hard character ceiling prevents accidental token blowouts
 *   - Returns an empty string (not null) if no history exists (stateless fallback)
 *
 * Future RAG extension point:
 *   This service can be extended to retrieve semantic context from a vector
 *   store without touching PromptBuilderService.
 */
@Injectable()
export class ContextBuilderService {
  private readonly logger = new Logger(ContextBuilderService.name);

  constructor(private readonly repo: ConversationRepository) {}

  /**
   * Builds a conversation context block to inject into the prompt.
   * Returns empty string if no prior context exists.
   */
  async buildContext(conversationId: string | undefined): Promise<string> {
    if (!conversationId) return '';

    try {
      // Fetch most-recent messages (descending), then reverse for chronological order
      const recent = await this.repo.getRecentMessages(conversationId, MAX_CONTEXT_TURNS);
      const chronological = [...recent].reverse() as ContextMessage[];

      if (chronological.length === 0) return '';

      const lines: string[] = ['CONVERSATION HISTORY:', ''];

      let totalChars = 0;
      for (const msg of chronological) {
        const prefix = msg.role === 'USER' ? 'User: ' : 'Sentinel AI: ';
        const line = `${prefix}${msg.content}`;

        if (totalChars + line.length > MAX_CONTEXT_CHARS) {
          lines.push('...(earlier messages truncated for context window)');
          break;
        }

        lines.push(line);
        totalChars += line.length;
      }

      lines.push('');
      return lines.join('\n');
    } catch (err) {
      this.logger.warn(`Context load failed for conversation ${conversationId}: ${err instanceof Error ? err.message : String(err)}`);
      return ''; // graceful degradation — proceed without history
    }
  }
}
