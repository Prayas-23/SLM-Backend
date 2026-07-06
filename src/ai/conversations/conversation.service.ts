import { Injectable, Logger, NotFoundException, ForbiddenException } from '@nestjs/common';
import { ConversationRepository } from './conversation.repository';
import { PrismaService } from '../../prisma/prisma.service';
import { CreateConversationDto, UpdateConversationDto } from './dto/conversation.dto';
import { AIMessageRole, AuditAction, AuditEntityType } from '@prisma/client';

/**
 * ConversationService
 *
 * Business logic for conversation lifecycle.
 * All operations are user-scoped — a user NEVER accesses another user's conversations.
 *
 * Architecture note:
 *   Messages are added through this service only — never by calling the
 *   repository directly from AISearchService. This ensures every message
 *   goes through audit logging.
 */
@Injectable()
export class ConversationService {
  private readonly logger = new Logger(ConversationService.name);

  constructor(
    private readonly repo:   ConversationRepository,
    private readonly prisma: PrismaService,
  ) {}

  // ── Conversation lifecycle ────────────────────────────────────────────────

  async create(actor: { id: string; name: string }, dto: CreateConversationDto) {
    const conv = await this.repo.createConversation(
      actor.id,
      dto.title ?? 'New Conversation',
    );
    await this.audit(actor, conv.id, AuditAction.CREATED, 'CONVERSATION_CREATED');
    return conv;
  }

  async list(userId: string, archived = false, page = 1, limit = 20) {
    return this.repo.findConversationsByUser(userId, archived, page, limit);
  }

  async findById(id: string, actor: { id: string }) {
    const conv = await this.repo.findConversationById(id, actor.id);
    if (!conv) throw new NotFoundException(`Conversation ${id} not found.`);
    return conv;
  }

  async update(id: string, actor: { id: string; name: string }, dto: UpdateConversationDto) {
    const conv = await this.repo.findConversationById(id, actor.id);
    if (!conv) throw new NotFoundException(`Conversation ${id} not found.`);

    await this.repo.updateConversation(id, actor.id, {
      title:    dto.title,
      archived: dto.archived,
    });

    const event = dto.archived !== undefined
      ? (dto.archived ? 'CONVERSATION_ARCHIVED' : 'CONVERSATION_UNARCHIVED')
      : 'CONVERSATION_RENAMED';

    await this.audit(actor, id, AuditAction.UPDATED, event);
    return { success: true };
  }

  async delete(id: string, actor: { id: string; name: string }) {
    const conv = await this.repo.findConversationById(id, actor.id);
    if (!conv) throw new NotFoundException(`Conversation ${id} not found.`);

    await this.repo.deleteConversation(id, actor.id);
    await this.audit(actor, id, AuditAction.DELETED, 'CONVERSATION_DELETED');
    return { success: true };
  }

  // ── Message persistence ───────────────────────────────────────────────────

  /**
   * Records a USER message. Auto-titles the conversation on the first message.
   */
  async addUserMessage(conversationId: string, actor: { id: string }, content: string) {
    await this.ensureOwnership(conversationId, actor.id);

    const msgCount = await this.repo.countMessages(conversationId);
    if (msgCount === 0) {
      await this.repo.autoTitleConversation(conversationId, actor.id, content);
    }

    await this.repo.addMessage(conversationId, {
      role:    AIMessageRole.USER,
      content,
    });
    await this.repo.touchConversation(conversationId, actor.id);
  }

  /**
   * Records an ASSISTANT message with full metadata.
   */
  async addAssistantMessage(
    conversationId: string,
    actor: { id: string },
    data: {
      content:          string;
      entity?:          string;
      operation?:       string;
      intent?:          string;
      promptTokens?:    number;
      completionTokens?: number;
      totalTokens?:     number;
      responseTimeMs?:  number;
      metadata?:        object;
    },
  ) {
    await this.ensureOwnership(conversationId, actor.id);
    await this.repo.addMessage(conversationId, { role: AIMessageRole.ASSISTANT, ...data });
    await this.repo.touchConversation(conversationId, actor.id);
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private async ensureOwnership(conversationId: string, userId: string) {
    const exists = await this.prisma.aIConversation.findFirst({
      where: { id: conversationId, userId },
      select: { id: true },
    });
    if (!exists) throw new ForbiddenException(`Access denied to conversation ${conversationId}.`);
  }

  private async audit(
    actor:  { id: string; name: string },
    convId: string,
    action: AuditAction,
    event:  string,
  ) {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorId:    actor.id,
          actorName:  actor.name,
          entityType: AuditEntityType.USER,
          entityId:   convId,
          action,
          metadata: { event } as never,
        },
      });
    } catch (err) {
      this.logger.error(`Conversation audit failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}
