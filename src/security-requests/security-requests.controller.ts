import {
  Controller, Get, Post, Patch, Delete,
  Param, Body, Query, Request,
  UseGuards, UseInterceptors, UploadedFile,
  HttpCode, HttpStatus, ParseUUIDPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UserRole } from '@prisma/client';
import { SecurityRequestsService } from './security-requests.service';
import { UploadLimitInterceptor } from '../common/interceptors/upload-limit.interceptor';
import {
  CreateSecurityRequestDto,
  UpdateSecurityRequestDto,
  UpdateRequestStatusDto,
  AddCommentDto,
  FilterSecurityRequestDto,
} from './dto/security-request.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('security-requests')
export class SecurityRequestsController {
  constructor(private readonly service: SecurityRequestsService) {}

  // ── List ────────────────────────────────────────────────────────────────────

  @Get()
  @Roles(
    UserRole.SECURITY_LEAD,
    UserRole.SECURITY_ANALYST,
    UserRole.APPLICATION_OWNER,
    UserRole.INFRASTRUCTURE_OWNER,
    UserRole.READ_ONLY,
  )
  findAll(@Query() filter: FilterSecurityRequestDto, @Request() req: any) {
    return this.service.findAll(filter, req.user.id);
  }

  // ── Single ──────────────────────────────────────────────────────────────────

  @Get(':id')
  @Roles(
    UserRole.SECURITY_LEAD,
    UserRole.SECURITY_ANALYST,
    UserRole.APPLICATION_OWNER,
    UserRole.INFRASTRUCTURE_OWNER,
    UserRole.READ_ONLY,
  )
  findOne(@Param('id') id: string) {
    return this.service.findOne(id);
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  @Post()
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  create(@Body() dto: CreateSecurityRequestDto, @Request() req: any) {
    return this.service.create(dto, { id: req.user.id, name: req.user.name });
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  @Patch(':id')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateSecurityRequestDto,
    @Request() req: any,
  ) {
    return this.service.update(id, dto, { id: req.user.id, name: req.user.name });
  }

  // ── Status Transition ───────────────────────────────────────────────────────

  @Patch(':id/status')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  updateStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateRequestStatusDto,
    @Request() req: any,
  ) {
    return this.service.updateStatus(id, dto, {
      id: req.user.id,
      name: req.user.name,
      role: req.user.role,
    });
  }

  // ── Delete (soft) ───────────────────────────────────────────────────────────

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.SECURITY_LEAD)
  remove(@Param('id', ParseUUIDPipe) id: string, @Request() req: any) {
    return this.service.remove(id, { id: req.user.id, name: req.user.name });
  }

  // ── Comments ────────────────────────────────────────────────────────────────

  @Get(':id/comments')
  @Roles(
    UserRole.SECURITY_LEAD,
    UserRole.SECURITY_ANALYST,
    UserRole.APPLICATION_OWNER,
    UserRole.INFRASTRUCTURE_OWNER,
    UserRole.READ_ONLY,
  )
  getComments(@Param('id') id: string) {
    return this.service.getComments(id);
  }

  @Post(':id/comments')
  @Roles(
    UserRole.SECURITY_LEAD,
    UserRole.SECURITY_ANALYST,
    UserRole.APPLICATION_OWNER,
    UserRole.INFRASTRUCTURE_OWNER,
  )
  addComment(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AddCommentDto,
    @Request() req: any,
  ) {
    return this.service.addComment(id, dto, {
      id: req.user.id,
      name: req.user.name,
      role: req.user.role,
    });
  }

  // ── Attachments ─────────────────────────────────────────────────────────────

  @Get(':id/attachments')
  @Roles(
    UserRole.SECURITY_LEAD,
    UserRole.SECURITY_ANALYST,
    UserRole.APPLICATION_OWNER,
    UserRole.INFRASTRUCTURE_OWNER,
    UserRole.READ_ONLY,
  )
  getAttachments(@Param('id') id: string) {
    return this.service.getAttachments(id);
  }

  @Post(':id/attachments')
  @Roles(UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST)
  @UseInterceptors(
    FileInterceptor('file', {
      storage: memoryStorage(),
    }),
    UploadLimitInterceptor,
  )
  uploadAttachment(
    @Param('id', ParseUUIDPipe) id: string,
    @UploadedFile() file: Express.Multer.File,
    @Request() req: any,
  ) {
    if (!file) throw new Error('No file uploaded.');
    return this.service.uploadAttachment(id, file, {
      id: req.user.id,
      name: req.user.name,
    });
  }
}
