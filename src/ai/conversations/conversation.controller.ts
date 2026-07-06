import {
  Controller, Get, Post, Patch, Delete,
  Param, Body, Query, Request, UseGuards,
  ParseBoolPipe, DefaultValuePipe,
  HttpCode, HttpStatus,
} from '@nestjs/common';
import { ConversationService } from './conversation.service';
import { CreateConversationDto, UpdateConversationDto } from './dto/conversation.dto';
import { JwtAuthGuard } from '../../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';

/**
 * ConversationController
 *
 * Routes:
 *   POST   /api/v1/ai/conversations          — create new conversation
 *   GET    /api/v1/ai/conversations          — list user's conversations
 *   GET    /api/v1/ai/conversations/:id      — get conversation with messages
 *   PATCH  /api/v1/ai/conversations/:id      — rename / archive
 *   DELETE /api/v1/ai/conversations/:id      — delete
 *
 * Every route is user-scoped — no cross-user data access is possible.
 */
@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('ai/conversations')
export class ConversationController {
  constructor(private readonly svc: ConversationService) {}

  @Post()
  async create(
    @Body() dto: CreateConversationDto,
    @Request() req: { user: { id: string; name: string } },
  ) {
    return this.svc.create(req.user, dto);
  }

  @Get()
  async list(
    @Request() req: { user: { id: string } },
    @Query('archived', new DefaultValuePipe(false), ParseBoolPipe) archived: boolean,
    @Query('page') page = '1',
    @Query('limit') limit = '20',
  ) {
    return this.svc.list(req.user.id, archived, Number(page), Number(limit));
  }

  @Get(':id')
  async findById(
    @Param('id') id: string,
    @Request() req: { user: { id: string } },
  ) {
    return this.svc.findById(id, req.user);
  }

  @Patch(':id')
  async update(
    @Param('id') id: string,
    @Body() dto: UpdateConversationDto,
    @Request() req: { user: { id: string; name: string } },
  ) {
    return this.svc.update(id, req.user, dto);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  async delete(
    @Param('id') id: string,
    @Request() req: { user: { id: string; name: string } },
  ) {
    return this.svc.delete(id, req.user);
  }
}
