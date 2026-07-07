import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AIProviderFactory } from './providers/ai-provider.factory';
import { SYSTEM_PROMPT } from './prompts/system.prompt';
import type { IAIProvider, AIMessage, AIResponse, AIHealthStatus } from './providers/ai-provider.interface';
import type { AISettingsResponse } from './dto/ai.dto';
import { SettingCategory, AuditAction, AuditEntityType } from '@prisma/client';

// ── Default configuration values ──────────────────────────────────────────────
const DEFAULTS = {
  provider:    'GEMINI',
  model:       'gemini-2.0-flash',
  temperature: 0.2,
  maxTokens:   1024,
  timeoutMs:   30_000,
};

/**
 * AIService — centralized AI infrastructure service.
 *
 * Responsibilities:
 *   - Load AI configuration from PlatformSetting (SettingCategory.AI)
 *   - Instantiate and refresh the active provider via AIProviderFactory
 *   - Execute AI requests (with system prompt injection)
 *   - Audit every test request and provider error
 *   - Expose health check status
 *
 * Business modules must NEVER call providers directly.
 * They must call AIService.
 *
 * Out of scope (Phase 2+):
 *   - Prompt engineering for specific tasks
 *   - Conversation history / session management
 *   - SQL generation / RAG / vector search
 */
@Injectable()
export class AIService implements OnModuleInit {
  private readonly logger = new Logger(AIService.name);

  /** Active provider — replaced on every refreshConfig() call */
  private provider: IAIProvider | null = null;

  /** Flat settings cache: key → value */
  private settingsCache: Record<string, string> = {};

  constructor(
    private readonly prisma: PrismaService,
    private readonly providerFactory: AIProviderFactory,
  ) {}

  async onModuleInit() {
    await this.refreshConfig();
  }

  // ── Configuration ───────────────────────────────────────────────────────────

  /**
   * Loads AI settings from PlatformSetting and rebuilds the active provider.
   * Called at startup and after every successful AI settings update.
   * Dynamic refresh — no server restart required.
   */
  async refreshConfig(): Promise<void> {
    const settings = await this.prisma.platformSetting.findMany({
      where: { category: SettingCategory.AI },
    });

    this.settingsCache = {};
    for (const s of settings) {
      this.settingsCache[s.key] = s.value;
    }

    if (!this.isEnabled()) {
      this.provider = null;
      this.logger.log('AI module is disabled — provider not initialized.');
      return;
    }

    const config = this.buildConfig();
    this.provider = this.providerFactory.create(config);

    this.logger.log(
      `AI config refreshed — provider: ${config.provider}, model: ${config.model}, enabled: true`,
    );
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  isEnabled(): boolean {
    return this.settingsCache['ai.enabled'] === 'true';
  }

  /**
   * Runs a health check against the configured provider.
   * Never throws — always resolves with a status object.
   */
  async healthCheck(): Promise<AIHealthStatus> {
    if (!this.isEnabled() || !this.provider) {
      return {
        provider:  this.settingsCache['ai.provider'] || DEFAULTS.provider,
        model:     this.settingsCache['ai.model']    || DEFAULTS.model,
        enabled:   false,
        reachable: false,
        error:     'AI module is disabled.',
      };
    }

    return this.provider.healthCheck();
  }

  /**
   * Sends a test prompt through the system prompt pipeline.
   * Writes an audit log record regardless of success or failure.
   */
  async testConnection(
    prompt: string,
    actor: { id: string; name: string },
  ): Promise<AIResponse> {
    if (!this.isEnabled() || !this.provider) {
      throw new Error('AI module is disabled. Enable it in Settings → AI Configuration.');
    }

    const messages: AIMessage[] = [
      { role: 'system', content: SYSTEM_PROMPT },
      { role: 'user',   content: prompt },
    ];

    let response: AIResponse;
    try {
      response = await this.provider.generateResponse(messages);

      await this.auditLog({
        actorId:   actor.id,
        actorName: actor.name,
        action:    AuditAction.CREATED,
        metadata: {
          event:     'AI_TEST_CONNECTION',
          provider:  response.provider,
          model:     response.model,
          latencyMs: response.latencyMs,
          success:   true,
        },
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);

      await this.auditLog({
        actorId:   actor.id,
        actorName: actor.name,
        action:    AuditAction.CREATED,
        metadata: {
          event:    'AI_TEST_CONNECTION',
          provider: this.settingsCache['ai.provider'] || DEFAULTS.provider,
          success:  false,
          error:    errorMessage,
        },
      });

      throw err;
    }

    return response;
  }

  /**
   * Executes a custom prompt pipeline. Used by internal modules (e.g. IntentDetection).
   * Does NOT automatically write an audit log (callers should audit business events).
   */
  async executePrompt(systemPrompt: string, userPrompt: string): Promise<AIResponse> {
    if (!this.isEnabled() || !this.provider) {
      throw new Error('AI module is disabled. Enable it in Settings → AI Configuration.');
    }

    const messages: AIMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user',   content: userPrompt },
    ];

    return this.provider.generateResponse(messages);
  }

  /**
   * Returns safe settings for the frontend — API key is masked.
   */
  getSettings(): AISettingsResponse {
    const rawKey = this.settingsCache['ai.apiKey'] || '';
    return {
      enabled:      this.isEnabled(),
      provider:     this.settingsCache['ai.provider']     || DEFAULTS.provider,
      model:        this.settingsCache['ai.model']        || DEFAULTS.model,
      temperature:  parseFloat(this.settingsCache['ai.temperature'] || String(DEFAULTS.temperature)),
      maxTokens:    parseInt(this.settingsCache['ai.maxTokens']  || String(DEFAULTS.maxTokens), 10),
      apiKeyMasked: this.maskSecret(rawKey),
    };
  }

  // ── Private helpers ─────────────────────────────────────────────────────────

  private buildConfig() {
    return {
      provider:    this.settingsCache['ai.provider']    || DEFAULTS.provider,
      apiKey:      this.settingsCache['ai.apiKey']      || process.env.OPENROUTER_API_KEY || '',
      model:       this.settingsCache['ai.model']       || DEFAULTS.model,
      temperature: parseFloat(this.settingsCache['ai.temperature'] || String(DEFAULTS.temperature)),
      maxTokens:   parseInt(this.settingsCache['ai.maxTokens']  || String(DEFAULTS.maxTokens), 10),
      timeoutMs:   parseInt(this.settingsCache['ai.timeoutMs']  || String(DEFAULTS.timeoutMs), 10),
    };
  }

  private maskSecret(value: string): string {
    if (!value || value.length < 8) return '••••••••';
    return value.slice(0, 4) + '••••••••' + value.slice(-4);
  }

  private async auditLog(params: {
    actorId:   string;
    actorName: string;
    action:    AuditAction;
    metadata?: unknown;
  }) {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorId:    params.actorId,
          actorName:  params.actorName,
          entityType: AuditEntityType.USER,
          entityId:   'ai-module',
          action:     params.action,
          metadata:   params.metadata as never,
        },
      });
    } catch (err) {
      // Audit failure must never crash the primary request
      this.logger.error(`AI audit log write failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
