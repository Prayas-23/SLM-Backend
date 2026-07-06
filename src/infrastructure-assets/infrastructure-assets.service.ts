import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateInfrastructureAssetDto, UpdateInfrastructureAssetDto, FilterInfrastructureAssetDto } from './dto/infrastructure-asset.dto';
import { PaginationDto } from '../common/dto/pagination.dto';

@Injectable()
export class InfrastructureAssetsService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(query: FilterInfrastructureAssetDto) {
    const { 
      page = 1, limit = 20, environment, startDate, endDate,
      search, serverId, ip, serverName, type, ownerName, criticality,
      sortBy, sortDir
    } = query;
    const skip = (page - 1) * limit;

    const where: any = { deletedAt: null };
    if (environment) where.environment = environment;
    if (serverId) where.serverId = { contains: serverId, mode: 'insensitive' };
    if (ip) where.ip = { contains: ip, mode: 'insensitive' };
    if (serverName) where.serverName = { contains: serverName, mode: 'insensitive' };
    if (type) where.type = type;
    if (criticality) where.criticality = criticality;
    if (ownerName) {
      where.assetOwner = { name: { contains: ownerName, mode: 'insensitive' } };
    }
    if (search) {
      where.OR = [
        { serverId: { contains: search, mode: 'insensitive' } },
        { ip: { contains: search, mode: 'insensitive' } },
        { serverName: { contains: search, mode: 'insensitive' } },
        { assetOwner: { name: { contains: search, mode: 'insensitive' } } },
      ];
    }
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate);
    }

    const isComputedSort = sortBy === 'openVulns' || sortBy === 'critVulns' || sortBy === 'sla';
    const fetchLimit = isComputedSort ? undefined : limit;
    const fetchSkip = isComputedSort ? undefined : skip;
    let prismaOrderBy: any = { createdAt: 'desc' };
    if (!isComputedSort && sortBy) {
       prismaOrderBy = { [sortBy]: sortDir || 'asc' };
    }

    const [data, total] = await this.prisma.$transaction([
      this.prisma.infrastructureAsset.findMany({
        where,
        include: {
          assetOwner: { select: { id: true, name: true, email: true } },
          applications: {
            include: {
              application: {
                select: {
                  id: true, appId: true, name: true, department: true,
                  owner: { select: { id: true, name: true, email: true } },
                },
              },
            },
          },
          securityRequests: {
            where: { deletedAt: null },
            include: {
              vulnerabilities: {
                where: { deletedAt: null },
                select: { id: true, severity: true, status: true, slaDueDate: true },
              },
            },
          },
        },
        skip: fetchSkip, take: fetchLimit,
        orderBy: prismaOrderBy,
      }),
      this.prisma.infrastructureAsset.count({ where }),
    ]);

    const enriched = (data as Array<typeof data[0]>).map((asset) => {
      const primaryApp = asset.applications?.[0]?.application ?? null;

      const allVulns = asset.securityRequests?.flatMap((req: any) => req.vulnerabilities) || [];
      const openVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED').length;
      const critVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
      const vulnsWithSla = allVulns.filter((v: any) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v: any) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
      
      return {
        ...asset,
        appOwnerName: primaryApp?.owner?.name ?? asset.appOwnerEmail ?? null,
        appOwnerEmail: primaryApp?.owner?.email ?? asset.appOwnerEmail ?? null,
        openVulnCount,
        critVulnCount,
        slaCompliancePct,
        openCvsFindingsCount: 0,
      };
    });

    for (const asset of enriched) {
      asset.openCvsFindingsCount = await this.prisma.continuousScanFinding.count({
        where: { assetId: asset.id, status: { not: 'PATCHED' } }
      });
    }

    if (isComputedSort && sortBy && sortDir) {
      enriched.sort((a, b) => {
        let va = 0, vb = 0;
        if (sortBy === 'openVulns') { va = a.openVulnCount; vb = b.openVulnCount; }
        if (sortBy === 'critVulns') { va = a.critVulnCount; vb = b.critVulnCount; }
        if (sortBy === 'sla') { va = a.slaCompliancePct; vb = b.slaCompliancePct; }
        return sortDir === 'asc' ? va - vb : vb - va;
      });
      const paginated = enriched.slice(skip, skip + limit);
      return { data: paginated, total, page, limit, totalPages: Math.ceil(total / limit) };
    }

    return { data: enriched, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async aggregate(query: FilterInfrastructureAssetDto) {
    const { 
      serverId, serverName, ip, environment, ownerName,
      criticality, type, startDate, endDate, search,
    } = query;

    const where: any = { deletedAt: null };

    if (serverId) where.serverId = { contains: serverId, mode: 'insensitive' };
    if (serverName) where.serverName = { contains: serverName, mode: 'insensitive' };
    if (ip) where.ip = { contains: ip, mode: 'insensitive' };
    if (environment) where.environment = environment;
    if (criticality) where.criticality = criticality;
    if (type) where.type = type;
    if (ownerName) {
      where.OR = [
        { assetOwner: { name: { contains: ownerName, mode: 'insensitive' } } },
        { appOwnerEmail: { contains: ownerName, mode: 'insensitive' } },
      ];
    }
    if (search) {
      const s = { contains: search, mode: 'insensitive' };
      const searchOr = [
        { serverId: s },
        { serverName: s },
        { ip: s },
        { criticality: s },
        { assetOwner: { name: s } },
        { appOwnerEmail: s },
      ];
      if (where.OR) {
        where.AND = [ { OR: where.OR }, { OR: searchOr } ];
        delete where.OR;
      } else {
        where.OR = searchOr;
      }
    }
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate);
    }

    const data = await this.prisma.infrastructureAsset.findMany({
      where,
      include: {
        securityRequests: {
          where: { deletedAt: null },
          include: {
            vulnerabilities: {
              where: { deletedAt: null },
              select: { severity: true, status: true, slaDueDate: true },
            },
          },
        },
      },
    });

    let totalActive = 0;
    let critical = 0;
    let totalSlaSum = 0;

    for (const asset of data) {
      totalActive++;
      const allVulns = asset.securityRequests?.flatMap((req: any) => req.vulnerabilities) || [];
      const critVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
      if (critVulnCount > 0) critical++;

      const vulnsWithSla = allVulns.filter((v: any) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v: any) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
      totalSlaSum += slaCompliancePct;
    }

    return {
      total: data.length,
      active: totalActive,
      critical,
      avgSla: data.length > 0 ? Math.round(totalSlaSum / data.length) : 100
    };
  }

  async findOne(id: string) {
    const asset = await this.prisma.infrastructureAsset.findFirst({
      where: { id, deletedAt: null },
      include: {
        assetOwner: { select: { id: true, name: true, email: true, staffId: true, department: true } },
        cloudResources: true,
        applications: {
          include: {
            application: {
              select: {
                id: true, appId: true, name: true, department: true,
                owner: { select: { id: true, name: true, email: true } },
              },
            },
          },
        },
        securityRequests: {
          where: { deletedAt: null },
          orderBy: { initiatedOn: 'desc' },
          include: {
            initiatedBy: { select: { id: true, name: true, email: true } },
            vulnerabilities: {
              where: { deletedAt: null },
              select: {
                id: true, vulnId: true, source: true, type: true, shortDesc: true,
                severity: true, cvss: true, status: true, pendingWith: true,
                reportedBy: true, reportedOn: true, slaDueDate: true, affectedComponent: true,
              },
            },
          },
        },
        scanFindings: {
          orderBy: { timestamp: 'desc' },
        },
      },
    });
    if (!asset) throw new NotFoundException(`Infrastructure asset ${id} not found.`);

    const primaryApp = asset.applications?.[0]?.application ?? null;

    const allVulns = asset.securityRequests.flatMap(req => req.vulnerabilities);
    const openVulnCount = allVulns.filter(v => v.status !== 'CLOSED').length;
    const critVulnCount = allVulns.filter(v => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
    const vulnsWithSla = allVulns.filter(v => v.status !== 'CLOSED' && v.slaDueDate);
    const withinSla = vulnsWithSla.filter(v => new Date(v.slaDueDate!) >= new Date()).length;
    const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;

    const openCvsFindingsCount = await this.prisma.continuousScanFinding.count({
      where: { assetId: id, status: { not: 'PATCHED' } }
    });

    const enriched = {
      ...asset,
      appOwnerName: primaryApp?.owner?.name ?? asset.appOwnerEmail ?? null,
      appOwnerEmail: primaryApp?.owner?.email ?? asset.appOwnerEmail ?? null,
      openVulnCount,
      critVulnCount,
      slaCompliancePct,
      openCvsFindingsCount,
    };
    return enriched;
  }

  async findScanFindings(assetId: string, query: PaginationDto) {
    const { page = 1, limit = 50, environment } = query;
    const skip = (page - 1) * limit;
    const where: any = { assetId };
    if (environment) where.assetEnv = environment;

    const [data, total] = await this.prisma.$transaction([
      this.prisma.scanFinding.findMany({
        where,
        skip, take: limit,
        orderBy: { timestamp: 'desc' },
      }),
      this.prisma.scanFinding.count({ where }),
    ]);

    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async create(dto: CreateInfrastructureAssetDto) {
    const exists = await this.prisma.infrastructureAsset.findFirst({
      where: { serverId: dto.serverId, deletedAt: null },
    });
    if (exists) throw new ConflictException('serverId already exists.');
    return this.prisma.infrastructureAsset.create({ data: dto as unknown as Parameters<typeof this.prisma.infrastructureAsset.create>[0]['data'] });
  }

  async update(id: string, dto: UpdateInfrastructureAssetDto) {
    await this.findOne(id);
    return this.prisma.infrastructureAsset.update({ where: { id }, data: dto as unknown as Parameters<typeof this.prisma.infrastructureAsset.update>[0]['data'] });
  }

  async remove(id: string) {
    await this.findOne(id);
    await this.prisma.infrastructureAsset.update({
      where: { id }, data: { deletedAt: new Date() },
    });
    return { message: 'Infrastructure asset deleted.' };
  }
}
