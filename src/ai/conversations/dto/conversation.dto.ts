import { IsOptional, IsString, IsBoolean, MaxLength, IsNotEmpty } from 'class-validator';

export class CreateConversationDto {
  @IsOptional()
  @IsString()
  @MaxLength(120)
  title?: string;
}

export class UpdateConversationDto {
  @IsOptional()
  @IsString()
  @MaxLength(120)
  title?: string;

  @IsOptional()
  @IsBoolean()
  archived?: boolean;
}

export class ConversationSearchDto {
  @IsOptional()
  page?: number;

  @IsOptional()
  limit?: number;

  @IsOptional()
  @IsBoolean()
  archived?: boolean;
}

// ── Response shapes ───────────────────────────────────────────────────────────

export interface ConversationMessageSummary {
  id: string;
  role: string;
  content: string;
  createdAt: string;
  entity?: string | null;
  operation?: string | null;
  promptTokens?: number | null;
  completionTokens?: number | null;
  totalTokens?: number | null;
  responseTimeMs?: number | null;
}

export interface ConversationSummary {
  id: string;
  title: string;
  archived: boolean;
  lastMessageAt: string | null;
  createdAt: string;
  _count: { messages: number };
}

export interface ConversationDetail extends ConversationSummary {
  messages: ConversationMessageSummary[];
}
