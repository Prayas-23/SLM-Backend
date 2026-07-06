import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AIService } from './ai.service';
import { IntentDetectionService } from './intent-detection.service';
import { QueryEngineService } from './query/query-engine.service';
import type { QueryResult } from './query/query-result.dto';
import { PromptBuilderService } from './prompt-builder/prompt-builder.service';
import { ResponseFormatterService } from './response/response-formatter.service';
import { SuggestionService } from './suggestions/suggestion.service';
import { ContextBuilderService } from './conversations/context-builder.service';
import { ConversationService } from './conversations/conversation.service';
import { AIEntity } from './dto/intent.dto';
import type { AISearchResponseDto } from './response/ai-response.dto';
import { AuditAction, AuditEntityType } from '@prisma/client';
import type { AIResponse } from './providers/ai-provider.interface';

/**
 * AISearchService — Phase 2.3 / 3.0 Orchestrator
 *
 * Full pipeline:
 *   NL query
 *     → ContextBuilder (load conversation history)
 *     → Intent Detection
 *     → RBAC Query Engine (Sentinel data path)
 *     → PromptBuilder (inject context + verified data)
 *     → Gemini
 *     → ResponseFormatter
 *     → Persist messages to ConversationService
 *
 * GENERAL_SECURITY path:
 *   Context → Intent → PromptBuilder (no DB query) → Gemini
 *
 * Security guarantees:
 *   - Gemini never accesses PostgreSQL
 *   - RBAC enforced on every query, even within conversations
 *   - Conversation context never bypasses the Query Engine
 *   - Users only access their own conversation context
 */
@Injectable()
export class AISearchService {
  private readonly logger = new Logger(AISearchService.name);

  constructor(
    private readonly prisma:        PrismaService,
    private readonly aiService:     AIService,
    private readonly intent:        IntentDetectionService,
    private readonly engine:        QueryEngineService,
    private readonly builder:       PromptBuilderService,
    private readonly formatter:     ResponseFormatterService,
    private readonly suggestions:   SuggestionService,
    private readonly contextSvc:    ContextBuilderService,
    private readonly convSvc:       ConversationService,
  ) {}

  /**
   * Main entry point — accepts a natural language query and an optional conversationId.
   * If conversationId is provided, context is loaded and messages are persisted.
   */
  async search(
    userQuery:       string,
    actor:           { id: string; name: string },
    conversationId?: string,
    page  = 1,
    limit = 20,
  ): Promise<AISearchResponseDto> {
    const startedAt = Date.now();

    // ── Step 1: Load conversation context (empty string if no session) ────────
    const conversationContext = await this.contextSvc.buildContext(conversationId);

    // ── Step 2: Persist user message ──────────────────────────────────────────
    if (conversationId) {
      await this.convSvc.addUserMessage(conversationId, actor, userQuery).catch((err) =>
        this.logger.warn(`Failed to persist user message: ${err instanceof Error ? err.message : err}`)
      );
    }

    // ── Step 3: Detect Intent ─────────────────────────────────────────────────
    const intentDto = await this.intent.detectIntent(userQuery, actor);

    // ── Step 4: RBAC Query Engine (data path only) ────────────────────────────
    const isGeneralSecurity = intentDto.entity === AIEntity.GENERAL_SECURITY;
    let queryResult: QueryResult | undefined;

    if (!isGeneralSecurity) {
      queryResult = await this.engine.execute(intentDto, actor, page, limit);
    }

    // ── Step 5: Build Prompt (inject context + verified data) ─────────────────
    const systemPrompt = this.builder.getSystemPrompt();
    const userPrompt   = this.builder.buildUserPrompt(intentDto, userQuery, queryResult, conversationContext);

    // ── Step 6: Generate AI Response ─────────────────────────────────────────
    let aiResponse: AIResponse;
    try {
      aiResponse = await this.aiService.executePrompt(systemPrompt, userPrompt);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.logger.error(`AI Search generation failed: ${msg}`);

      const formatted = this.formatter.formatError(msg);
      await this.auditSearch(actor, intentDto, 0, false, msg, Date.now() - startedAt);

      if (conversationId) {
        await this.convSvc.addAssistantMessage(conversationId, actor, {
          content: formatted.answer,
        }).catch(() => null);
      }

      return {
        success: false,
        response: formatted,
        pipeline: {
          entity:      intentDto.entity,
          operation:   intentDto.operation,
          confidence:  intentDto.confidence,
          resultCount: 0,
          filtersApplied: intentDto.filters,
        },
        error: 'AI response generation failed.',
      };
    }

    // ── Step 7: Suggestions ───────────────────────────────────────────────────
    const suggestionList = this.suggestions.generate(intentDto);

    // ── Step 8: Format final response ─────────────────────────────────────────
    const formatted = this.formatter.format(aiResponse, suggestionList);

    const executionTimeMs = Date.now() - startedAt;

    // ── Step 9: Persist assistant message ─────────────────────────────────────
    if (conversationId) {
      await this.convSvc.addAssistantMessage(conversationId, actor, {
        content:          formatted.answer,
        entity:           intentDto.entity,
        operation:        intentDto.operation,
        intent:           intentDto.operation,
        promptTokens:     aiResponse.promptTokens,
        completionTokens: aiResponse.completionTokens,
        totalTokens:      aiResponse.totalTokens,
        responseTimeMs:   executionTimeMs,
        metadata: {
          confidence:  intentDto.confidence,
          resultCount: queryResult?.totalRecords ?? 0,
          filters:     intentDto.filters,
        },
      }).catch(() => null);
    }

    // ── Step 10: Audit ────────────────────────────────────────────────────────
    await this.auditSearch(
      actor, intentDto, queryResult?.totalRecords ?? 0, true, undefined, executionTimeMs,
      aiResponse.promptTokens, aiResponse.completionTokens, aiResponse.totalTokens,
      conversationId,
    );

    return {
      success:  true,
      response: formatted,
      pipeline: {
        entity:         intentDto.entity,
        operation:      intentDto.operation,
        confidence:     intentDto.confidence,
        resultCount:    queryResult?.totalRecords ?? 0,
        filtersApplied: intentDto.filters,
      },
    };
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private async auditSearch(
    actor:            { id: string; name: string },
    intentDto:        { entity: string; operation: string; filters: object; confidence: number },
    resultCount:      number,
    success:          boolean,
    failureReason:    string | undefined,
    totalTimeMs:      number,
    promptTokens?:    number,
    completionTokens?: number,
    totalTokens?:     number,
    conversationId?:  string,
  ) {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorId:    actor.id,
          actorName:  actor.name,
          entityType: AuditEntityType.USER,
          entityId:   conversationId ?? 'ai-search',
          action:     AuditAction.CREATED,
          metadata: {
            event:    'AI_SEARCH',
            entity:   intentDto.entity,
            operation: intentDto.operation,
            filters:  intentDto.filters,
            confidence: intentDto.confidence,
            resultCount,
            success,
            failureReason,
            totalTimeMs,
            conversationId,
            tokens: { prompt: promptTokens, completion: completionTokens, total: totalTokens },
          } as never,
        },
      });
    } catch (err) {
      this.logger.error(`AI Search audit failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
