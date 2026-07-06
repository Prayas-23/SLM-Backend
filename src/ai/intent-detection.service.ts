import { Injectable, Logger } from '@nestjs/common';
import { AIService } from './ai.service';
import { INTENT_DETECTION_PROMPT } from './prompts/intent.prompt';
import { IntentDto, AIOperation, AIEntity } from './dto/intent.dto';
import { PrismaService } from '../prisma/prisma.service';
import { AuditAction, AuditEntityType } from '@prisma/client';

/**
 * IntentDetectionService
 *
 * Phase 2.1 — Converts natural language queries into structured IntentDto JSON.
 * It does NOT execute queries, access the DB, or answer the user directly.
 */
@Injectable()
export class IntentDetectionService {
  private readonly logger = new Logger(IntentDetectionService.name);

  // Minimum confidence threshold to consider an intent valid
  private readonly CONFIDENCE_THRESHOLD = 0.70;

  constructor(
    private readonly aiService: AIService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Detects the intent of a user's natural language query.
   *
   * @param query The raw user input (e.g., "Show all critical vulnerabilities")
   * @param actor The user making the request (for auditing)
   * @returns A structured IntentDto
   */
  async detectIntent(
    query: string,
    actor: { id: string; name: string },
  ): Promise<IntentDto> {
    const startedAt = Date.now();
    let parsedIntent: IntentDto;
    let providerName = 'UNKNOWN';
    let latency = 0;

    try {
      // 1. Execute prompt via AIService
      const response = await this.aiService.executePrompt(
        INTENT_DETECTION_PROMPT,
        query,
      );
      providerName = response.provider;
      latency = response.latencyMs;

      // 2. Parse and validate JSON response
      parsedIntent = this.parseResponse(response.text);

      // 3. Apply confidence threshold
      if (parsedIntent.confidence < this.CONFIDENCE_THRESHOLD) {
        this.logger.warn(`Intent confidence too low (${parsedIntent.confidence}). Falling back to UNKNOWN.`);
        parsedIntent.operation = AIOperation.UNKNOWN;
        parsedIntent.entity = AIEntity.UNKNOWN;
      }

    } catch (err) {
      this.logger.error(`Failed to detect intent: ${err instanceof Error ? err.message : String(err)}`);
      // Fallback to unknown on any failure (timeout, parsing error, provider error)
      parsedIntent = {
        operation: AIOperation.UNKNOWN,
        entity: AIEntity.UNKNOWN,
        filters: {},
        confidence: 0,
      };
    }

    // 4. Write Audit Log
    await this.auditLog(query, parsedIntent, providerName, latency, actor);

    return parsedIntent;
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  /**
   * Strips markdown formatting (like ```json ... ```) and parses the response.
   * Validates enum values loosely to ensure structural integrity.
   */
  private parseResponse(rawText: string): IntentDto {
    try {
      // Sometimes LLMs wrap JSON in markdown blocks despite instructions not to.
      let cleanText = rawText.trim();
      if (cleanText.startsWith('\`\`\`json')) {
        cleanText = cleanText.substring(7);
      }
      if (cleanText.startsWith('\`\`\`')) {
        cleanText = cleanText.substring(3);
      }
      if (cleanText.endsWith('\`\`\`')) {
        cleanText = cleanText.substring(0, cleanText.length - 3);
      }

      const parsed = JSON.parse(cleanText.trim());

      // Validate enums (fallback to UNKNOWN if invalid)
      const operation = Object.values(AIOperation).includes(parsed.operation) 
        ? parsed.operation 
        : AIOperation.UNKNOWN;
        
      const entity = Object.values(AIEntity).includes(parsed.entity) 
        ? parsed.entity 
        : AIEntity.UNKNOWN;

      return {
        operation,
        entity,
        filters: parsed.filters || {},
        confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0,
      };
    } catch (err) {
      this.logger.error(`JSON Parse Error on AI response: ${rawText}`);
      throw new Error('Invalid JSON response from AI provider');
    }
  }

  private async auditLog(
    query: string,
    intent: IntentDto,
    provider: string,
    latencyMs: number,
    actor: { id: string; name: string }
  ) {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorId:    actor.id,
          actorName:  actor.name,
          entityType: AuditEntityType.USER, // Reusing USER as generic actor context for now
          entityId:   'ai-intent-engine',
          action:     AuditAction.CREATED,
          metadata: {
            event: 'INTENT_DETECTED',
            query,
            intent,
            provider,
            latencyMs,
          } as never,
        },
      });
    } catch (err) {
      this.logger.error(`Intent audit log failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
