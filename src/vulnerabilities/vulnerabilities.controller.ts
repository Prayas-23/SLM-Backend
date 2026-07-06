import {
  Controller, Get, Post, Patch, Delete,
  Param, Body, Query, Request,
  UseGuards, UseInterceptors, UploadedFile,
  HttpCode, HttpStatus, ParseUUIDPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UserRole } from '@prisma/client';
import { VulnerabilitiesService } from './vulnerabilities.service';
import { UploadLimitInterceptor } from '../common/interceptors/upload-limit.interceptor';
import {
  CreateVulnerabilityDto,
  UpdateVulnerabilityDto,
  UpdateVulnerabilityStatusDto,
  AddVulnCommentDto,
  FilterVulnerabilityDto,
} from './dto/vulnerability.dto';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../auth/decorators/roles.decorator';

const ALL_ROLES = [
  UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST,
  UserRole.APPLICATION_OWNER, UserRole.INFRASTRUCTURE_OWNER, UserRole.READ_ONLY,
];
const WRITE_ROLES = [UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST];
const COMMENT_ROLES = [
  UserRole.SECURITY_LEAD, UserRole.SECURITY_ANALYST,
  UserRole.APPLICATION_OWNER, UserRole.INFRASTRUCTURE_OWNER,
];

@UseGuards(JwtAuthGuard, RolesGuard)
@Controller('vulnerabilities')
export class VulnerabilitiesController {
  constructor(private readonly service: VulnerabilitiesService) {}

  // ── List ────────────────────────────────────────────────────────────────────

  @Get()
  @Roles(...ALL_ROLES)
  findAll(@Query() filter: FilterVulnerabilityDto) {
    return this.service.findAll(filter);
  }

  // ── Single ──────────────────────────────────────────────────────────────────

  @Get(':id')
  @Roles(...ALL_ROLES)
  findOne(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.findOne(id);
  }

  // ── Create ──────────────────────────────────────────────────────────────────

  @Post()
  @Roles(...WRITE_ROLES)
  create(@Body() dto: CreateVulnerabilityDto, @Request() req: any) {
    return this.service.create(dto, {
      id: req.user.id, name: req.user.name, role: req.user.role,
    });
  }

  // ── Update ──────────────────────────────────────────────────────────────────

  @Patch(':id')
  @Roles(...WRITE_ROLES)
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateVulnerabilityDto,
    @Request() req: any,
  ) {
    return this.service.update(id, dto, {
      id: req.user.id, name: req.user.name, role: req.user.role,
    });
  }

  // ── Status Transition ───────────────────────────────────────────────────────

  @Patch(':id/status')
  @Roles(...WRITE_ROLES)
  updateStatus(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateVulnerabilityStatusDto,
    @Request() req: any,
  ) {
    return this.service.updateStatus(id, dto, {
      id: req.user.id, name: req.user.name, role: req.user.role,
    });
  }

  // ── Delete (soft) ───────────────────────────────────────────────────────────

  @Delete(':id')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.SECURITY_LEAD)
  remove(@Param('id', ParseUUIDPipe) id: string, @Request() req: any) {
    return this.service.remove(id, { id: req.user.id, name: req.user.name });
  }

  // ── Lifecycle Logs ──────────────────────────────────────────────────────────

  @Get(':id/lifecycle')
  @Roles(...ALL_ROLES)
  getLifecycleLogs(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getLifecycleLogs(id);
  }

  // ── Comments ────────────────────────────────────────────────────────────────

  @Get(':id/comments')
  @Roles(...ALL_ROLES)
  getComments(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getComments(id);
  }

  @Post(':id/comments')
  @Roles(...COMMENT_ROLES)
  addComment(
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: AddVulnCommentDto,
    @Request() req: any,
  ) {
    return this.service.addComment(id, dto, {
      id: req.user.id, name: req.user.name, role: req.user.role,
    });
  }

  // ── Attachments ─────────────────────────────────────────────────────────────

  @Get(':id/attachments')
  @Roles(...ALL_ROLES)
  getAttachments(@Param('id', ParseUUIDPipe) id: string) {
    return this.service.getAttachments(id);
  }

  @Post(':id/attachments')
  @Roles(...WRITE_ROLES)
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
      id: req.user.id, name: req.user.name,
    });
  }
}
