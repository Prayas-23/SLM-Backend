import {
  Controller,
  Get,
  Post,
  Body,
  UseGuards,
  Request,
} from '@nestjs/common';
import { AIService } from './ai.service';
import { IntentDetectionService } from './intent-detection.service';
import { QueryEngineService } from './query/query-engine.service';
import { AISearchService } from './ai-search.service';
import { TestAIConnectionDto, DetectIntentDto } from './dto/ai.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';
import { UserRole } from '@prisma/client';

/**
 * AIController
 *
 * Routes:
 *   GET  /api/v1/ai/health   — provider health status
 *   GET  /api/v1/ai/settings — current settings (key masked)
 *   POST /api/v1/ai/test     — connectivity test
 *   POST /api/v1/ai/intent   — Phase 2.1: intent classification only
 *   POST /api/v1/ai/query    — Phase 2.2: intent → RBAC → data (no LLM response)
 *   POST /api/v1/ai/search   — Phase 2.3: full NL → intent → data → LLM → response
 */
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('ai')
export class AIController {
  constructor(
    private readonly aiService:      AIService,
    private readonly intentService:  IntentDetectionService,
    private readonly queryEngine:    QueryEngineService,
    private readonly searchService:  AISearchService,
  ) {}

  /**
   * GET /api/v1/ai/health
   *
   * Returns current provider, model, enabled status and reachability.
   * Available to all authenticated users so dashboards can show AI status.
   */
  @Get('health')
  async health() {
    return this.aiService.healthCheck();
  }

  /**
   * GET /api/v1/ai/settings
   *
   * Returns the current AI configuration — API key is always masked.
   * SECURITY_LEAD only.
   */
  @Get('settings')
  @Roles(UserRole.SECURITY_LEAD)
  getSettings() {
    return this.aiService.getSettings();
  }

  /**
   * POST /api/v1/ai/test
   *
   * Sends a simple prompt to the configured provider to verify connectivity.
   * Defaults to a standard ping if no prompt is provided.
   * Writes an audit log entry regardless of success or failure.
   * SECURITY_LEAD only.
   */
  @Post('test')
  @Roles(UserRole.SECURITY_LEAD)
  async testConnection(
    @Body() dto: TestAIConnectionDto,
    @Request() req: { user: { id: string; name: string } },
  ) {
    const prompt = dto.prompt?.trim() ||
      'Hello Sentinel AI. Please confirm you are operational and briefly describe your purpose in one sentence.';

    const response = await this.aiService.testConnection(prompt, req.user);

    return {
      success:  true,
      provider: response.provider,
      model:    response.model,
      response: response.text,
      latencyMs: response.latencyMs,
      tokens:   {
        prompt:     response.promptTokens,
        completion: response.completionTokens,
        total:      response.totalTokens,
      },
    };
  }

  /**
   * POST /api/v1/ai/intent
   *
   * Tests the intent detection engine. Returns the parsed structured IntentDto.
   * Does NOT execute the query against the database.
   */
  @Post('intent')
  async testIntent(
    @Body() dto: DetectIntentDto,
    @Request() req: { user: { id: string; name: string } },
  ) {
    return this.intentService.detectIntent(dto.query, req.user);
  }

  /**
   * POST /api/v1/ai/query
   *
   * Full Phase 2.2 pipeline:
   *   natural language → IntentDetection → RBAC → QueryBuilder → QueryResult
   *
   * Accepts: { query: string, page?: number, limit?: number }
   * Returns: QueryResult<T> — verified structured data only.
   * No LLM response is generated. No SQL.
   */
  @Post('query')
  async query(
    @Body() dto: DetectIntentDto & { page?: number; limit?: number },
    @Request() req: { user: { id: string; name: string } },
  ) {
    const intent = await this.intentService.detectIntent(dto.query, req.user);
    return this.queryEngine.execute(intent, req.user, dto.page ?? 1, dto.limit ?? 20);
  }

  /**
   * POST /api/v1/ai/search
   *
   * Phase 2.3 — Full AI Search pipeline:
   *   Natural language → Intent → RBAC → Prisma → PromptBuilder → Gemini → AIResponseDto
   *
   * This is the production endpoint used by the frontend search bar.
   * No SQL generated. Gemini only explains verified data.
   * GENERAL_SECURITY queries bypass the Query Engine safely.
   */
  @Post('search')
  async search(
    @Body() dto: DetectIntentDto & { page?: number; limit?: number },
    @Request() req: { user: { id: string; name: string } },
  ) {
    return this.searchService.search(
      dto.query,
      req.user,
      dto.conversationId,
      dto.page ?? 1,
      dto.limit ?? 20,
    );
  }
}
