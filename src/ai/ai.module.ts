import { Module } from '@nestjs/common';
import { AIService } from './ai.service';
import { AIController } from './ai.controller';
import { AIProviderFactory } from './providers/ai-provider.factory';
import { IntentDetectionService } from './intent-detection.service';
import { QueryEngineService } from './query/query-engine.service';
import { QueryBuilderService } from './query/query-builder.service';
import { RbacQueryService } from './query/rbac-query.service';
import { PromptBuilderService } from './prompt-builder/prompt-builder.service';
import { ResponseFormatterService } from './response/response-formatter.service';
import { SuggestionService } from './suggestions/suggestion.service';
import { AISearchService } from './ai-search.service';
import { ConversationService } from './conversations/conversation.service';
import { ConversationRepository } from './conversations/conversation.repository';
import { ConversationController } from './conversations/conversation.controller';
import { ContextBuilderService } from './conversations/context-builder.service';
import { PrismaModule } from '../prisma/prisma.module';

/**
 * AIModule — Sentinel AI Infrastructure
 *
 * Phase 1:   AIService, AIProviderFactory, GeminiProvider
 * Phase 2.1: IntentDetectionService
 * Phase 2.2: QueryEngineService, QueryBuilderService, RbacQueryService
 * Phase 2.3: PromptBuilderService, ResponseFormatterService, SuggestionService, AISearchService
 * Phase 3.0: ConversationService, ConversationRepository, ContextBuilderService
 */
@Module({
  imports: [PrismaModule],
  controllers: [AIController, ConversationController],
  providers: [
    AIProviderFactory,
    AIService,
    IntentDetectionService,
    RbacQueryService,
    QueryBuilderService,
    QueryEngineService,
    PromptBuilderService,
    ResponseFormatterService,
    SuggestionService,
    ConversationRepository,
    ContextBuilderService,
    ConversationService,
    AISearchService,
  ],
  exports: [AIService, IntentDetectionService, QueryEngineService, AISearchService, ConversationService],
})
export class AIModule {}
