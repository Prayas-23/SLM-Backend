import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateFindingDto, FilterFindingDto, UpdateFindingStatusDto } from './dto/finding.dto';
import { FindingStatus } from '@prisma/client';
import { ComplianceMappingService } from '../compliance/compliance-mapping.service';

@Injectable()
export class FindingsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly complianceMapping: ComplianceMappingService,
  ) {}

  async create(dto: CreateFindingDto) {
    const year = new Date().getFullYear();
    const count = await this.prisma.finding.count();
    const findingId = `FND-${year}-${String(count + 1).padStart(4, '0')}`;

    const finding = await this.prisma.finding.create({
      data: {
        findingId,
        title: dto.title,
        description: dto.description,
        severity: dto.severity,
        sourceType: dto.sourceType,
        sourceId: dto.sourceId,
        cvssScore: dto.cvssScore,
        cveId: dto.cveId,
        recommendation: dto.recommendation,
        evidence: dto.evidence,
      },
    });

    if (dto.sourceType === 'CVS') {
      try {
        await this.convertToVulnerability(finding.id);
      } catch (e) {
        // Log error but don't fail the finding creation
        console.error('Failed to auto-convert CVS finding', e);
      }
    }

    return finding;
  }

  async findAll(filters: FilterFindingDto) {
    const { page = 1, limit = 10, sourceType, severity, status, sourceId, convertedToVulnerability } = filters;
    const skip = (page - 1) * limit;

    const where: any = {};
    if (sourceType) where.sourceType = sourceType;
    if (severity) where.severity = severity;
    if (status) where.status = status;
    if (sourceId) where.sourceId = sourceId;
    if (convertedToVulnerability !== undefined) where.convertedToVulnerability = convertedToVulnerability;

    const [data, total] = await Promise.all([
      this.prisma.finding.findMany({
        where,
        skip,
        take: Number(limit),
        orderBy: { createdAt: 'desc' },
        include: {
          securityRequest: {
            select: { reqId: true, targetAppId: true, targetApp: { select: { name: true } } }
          },
          vulnerability: {
            select: { vulnId: true }
          }
        }
      }),
      this.prisma.finding.count({ where }),
    ]);

    return {
      data,
      total,
      page: Number(page),
      limit: Number(limit),
      totalPages: Math.ceil(total / limit),
    };
  }

  async findOne(id: string) {
    const finding = await this.prisma.finding.findUnique({
      where: { id },
      include: {
        securityRequest: true,
        vulnerability: true,
      },
    });
    if (!finding) throw new NotFoundException('Finding not found');
    return finding;
  }

  async updateStatus(id: string, dto: UpdateFindingStatusDto) {
    const finding = await this.findOne(id);
    if (finding.convertedToVulnerability && dto.status !== FindingStatus.ACCEPTED) {
      throw new BadRequestException('Cannot change status of a finding that has already been converted to a vulnerability');
    }

    return this.prisma.finding.update({
      where: { id },
      data: { status: dto.status },
    });
  }

  async convertToVulnerability(id: string) {
    const finding = await this.findOne(id);
    if (finding.convertedToVulnerability) {
      throw new BadRequestException('Finding is already converted to a vulnerability');
    }

    // Logic to convert finding to vulnerability
    // Find count to generate VulnID
    const count = await this.prisma.vulnerability.count();
    const reqPart = finding.securityRequest?.reqId || 'VULN';
    const vulnId = `${reqPart}-${String(count + 1).padStart(3, '0')}`;

    const vuln = await this.prisma.vulnerability.create({
      data: {
        vulnId,
        requestId: finding.sourceId, // Note: Assuming finding is linked to a security request
        source: finding.sourceType,
        type: 'Vulnerability',
        shortDesc: finding.title,
        description: finding.description,
        severity: finding.severity,
        cvss: finding.cvssScore,
        cve: finding.cveId,
        remediation: finding.recommendation,
        poc: finding.evidence,
        findingId: finding.id,
      },
    });

    await this.prisma.finding.update({
      where: { id },
      data: { 
        convertedToVulnerability: true,
        status: FindingStatus.ACCEPTED
      },
    });

    // ── Auto-map to Security Controls (fire-and-forget) ──────────────────
    void this.complianceMapping.mapVulnerability(vuln.id, vuln.type);

    return vuln;
  }
}
