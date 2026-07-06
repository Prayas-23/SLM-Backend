import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { PaginationDto } from '../common/dto/pagination.dto';
import { Environment, Severity } from '@prisma/client';
import { IsOptional, IsEnum, IsString } from 'class-validator';

export class FilterScanFindingDto extends PaginationDto {
  @IsOptional() @IsString() assetId?: string;
  @IsOptional() @IsString() assetName?: string;
  @IsOptional() @IsEnum(Environment) environment?: Environment;
  @IsOptional() @IsEnum(Severity) severity?: Severity;
  @IsOptional() @IsString() status?: string;
  @IsOptional() @IsString() vaReqId?: string;
}

@Injectable()
export class ScanFindingsService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(query: FilterScanFindingDto) {
    const { page = 1, limit = 50, assetId, assetName, environment, severity, status, vaReqId } = query;
    const skip = (page - 1) * limit;

    const where: any = {};
    if (assetId) where.assetId = assetId;
    if (assetName) where.assetName = { contains: assetName, mode: 'insensitive' };
    if (environment) where.assetEnv = environment;
    if (severity) where.severity = severity;
    if (status) where.status = status;
    if (vaReqId !== undefined) where.vaReqId = vaReqId;

    const [data, total] = await this.prisma.$transaction([
      this.prisma.scanFinding.findMany({
        where,
        skip,
        take: limit,
        orderBy: { timestamp: 'desc' },
        include: {
          infrastructureAsset: { select: { id: true, serverId: true, serverName: true, ip: true, environment: true } },
          vulnerability: { select: { id: true, vulnId: true, status: true } },
        },
      }),
      this.prisma.scanFinding.count({ where }),
    ]);

    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async findOne(id: string) {
    const finding = await this.prisma.scanFinding.findFirst({
      where: { id },
      include: {
        infrastructureAsset: { select: { id: true, serverId: true, serverName: true, ip: true, environment: true } },
        vulnerability: {
          select: {
            id: true, vulnId: true, status: true, pendingWith: true,
            assignedTo: { select: { id: true, name: true, email: true } },
          },
        },
      },
    });
    if (!finding) throw new NotFoundException(`Scan finding '${id}' not found.`);
    return finding;
  }

  /** Promote a scan finding to a Vulnerability Assessment security request */
  async createVaRequest(id: string, actor: { id: string; name: string }) {
    const finding = await this.findOne(id);

    // Create or find a VAPT security request for this asset (partner = Qualys)
    const reqId = `VA-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;

    const request = await this.prisma.securityRequest.create({
      data: {
        reqId,
        source: 'VAPT',
        environment: finding.assetEnv,
        targetInfraId: finding.assetId ?? undefined,
        partner: 'Qualys',
        initiatedById: actor.id,
        assessmentMeta: {
          vaptType: 'VULNERABILITY_ASSESSMENT',
          scanFindingId: finding.id,
          assetName: finding.assetName,
          assetIp: finding.assetIp,
        },
      },
    });

    // Link this finding's VA request
    await this.prisma.scanFinding.update({
      where: { id },
      data: { vaReqId: request.reqId },
    });

    return { message: 'VA request created.', reqId: request.reqId, requestId: request.id };
  }
}
