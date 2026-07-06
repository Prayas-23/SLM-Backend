import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { AIMessageRole } from '@prisma/client';

/**
 * ConversationRepository
 *
 * Thin data-access layer for AIConversation and AIMessage.
 * No business logic here — only Prisma calls.
 */
@Injectable()
export class ConversationRepository {
  constructor(private readonly prisma: PrismaService) {}

  // ── Conversations ─────────────────────────────────────────────────────────

  async createConversation(userId: string, title: string, provider?: string, model?: string) {
    return this.prisma.aIConversation.create({
      data: { userId, title, provider, model },
      select: { id: true, title: true, archived: true, lastMessageAt: true, createdAt: true },
    });
  }

  async findConversationsByUser(
    userId: string,
    archived = false,
    page = 1,
    limit = 20,
  ) {
    return this.prisma.aIConversation.findMany({
      where: { userId, archived },
      select: {
        id: true, title: true, archived: true, lastMessageAt: true, createdAt: true,
        _count: { select: { messages: true } },
      },
      orderBy: { lastMessageAt: 'desc' },
      skip: (page - 1) * limit,
      take: limit,
    });
  }

  async findConversationById(id: string, userId: string) {
    return this.prisma.aIConversation.findFirst({
      where: { id, userId },
      select: {
        id: true, title: true, archived: true, lastMessageAt: true, createdAt: true,
        _count: { select: { messages: true } },
        messages: {
          select: {
            id: true, role: true, content: true, createdAt: true,
            entity: true, operation: true,
            promptTokens: true, completionTokens: true, totalTokens: true, responseTimeMs: true,
          },
          orderBy: { createdAt: 'asc' },
        },
      },
    });
  }

  async updateConversation(id: string, userId: string, data: { title?: string; archived?: boolean }) {
    return this.prisma.aIConversation.updateMany({
      where: { id, userId },
      data,
    });
  }

  async deleteConversation(id: string, userId: string) {
    return this.prisma.aIConversation.deleteMany({ where: { id, userId } });
  }

  async touchConversation(id: string, userId: string) {
    return this.prisma.aIConversation.updateMany({
      where: { id, userId },
      data: { lastMessageAt: new Date() },
    });
  }

  async autoTitleConversation(id: string, userId: string, firstUserMessage: string) {
    const title = firstUserMessage.length > 60
      ? firstUserMessage.substring(0, 57) + '...'
      : firstUserMessage;
    return this.prisma.aIConversation.updateMany({
      where: { id, userId, title: 'New Conversation' },
      data: { title },
    });
  }

  // ── Messages ──────────────────────────────────────────────────────────────

  async addMessage(conversationId: string, data: {
    role: AIMessageRole;
    content: string;
    entity?: string;
    operation?: string;
    intent?: string;
    promptTokens?: number;
    completionTokens?: number;
    totalTokens?: number;
    responseTimeMs?: number;
    metadata?: object;
  }) {
    return this.prisma.aIMessage.create({
      data: { conversationId, ...data, metadata: data.metadata as never },
      select: { id: true, role: true, content: true, createdAt: true },
    });
  }

  /**
   * Load the most recent N exchange pairs (user + assistant).
   * Used by ContextBuilderService to build conversation context.
   */
  async getRecentMessages(conversationId: string, limit: number) {
    return this.prisma.aIMessage.findMany({
      where: { conversationId },
      select: { role: true, content: true, entity: true, operation: true, createdAt: true },
      orderBy: { createdAt: 'desc' },
      take: limit * 2, // fetch pairs (user + assistant)
    });
  }

  async countMessages(conversationId: string): Promise<number> {
    return this.prisma.aIMessage.count({ where: { conversationId } });
  }
}
