import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateApplicationDto } from './dto/create-application.dto';
import { UpdateApplicationDto } from './dto/update-application.dto';
import { FilterApplicationDto } from './dto/filter-application.dto';
import { AuditEntityType, AuditAction } from '@prisma/client';
import { calculateApplicationScores } from './scoring.util';

@Injectable()
export class ApplicationsService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(query: FilterApplicationDto) {
    const { 
      page = 1, limit = 20, environment, ownerId, criticality, startDate, endDate,
      search, type, department, vaptStatus, sortBy, sortDir,
      appId, name, ownerName
    } = query;
    const skip = (page - 1) * limit;

    const where: any = { deletedAt: null };
    if (environment) where.environment = environment;
    if (ownerId) where.ownerId = ownerId;
    if (criticality) where.criticality = criticality;
    if (type) where.type = type;
    if (department) where.department = { contains: department, mode: 'insensitive' };
    if (vaptStatus) where.vaptStatus = vaptStatus;
    if (appId) where.appId = { contains: appId, mode: 'insensitive' };
    if (name) where.name = { contains: name, mode: 'insensitive' };
    if (ownerName) {
      const ownerOr = [
        { owner: { name: { contains: ownerName, mode: 'insensitive' } } },
        { ownerEmail: { contains: ownerName, mode: 'insensitive' } }
      ];
      if (where.OR) {
        where.AND = [{ OR: where.OR }, { OR: ownerOr }];
        delete where.OR;
      } else {
        where.OR = ownerOr;
      }
    }
    if (search) {
      const searchOr = [
        { appId: { contains: search, mode: 'insensitive' } },
        { name: { contains: search, mode: 'insensitive' } },
        { department: { contains: search, mode: 'insensitive' } },
        { ownerEmail: { contains: search, mode: 'insensitive' } },
        { owner: { name: { contains: search, mode: 'insensitive' } } },
      ];
      if (where.OR) {
        where.AND = where.AND || [];
        where.AND.push({ OR: where.OR }, { OR: searchOr });
        delete where.OR;
      } else if (where.AND) {
        where.AND.push({ OR: searchOr });
      } else {
        where.OR = searchOr;
      }
    }
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate);
    }

    const isComputedSort = sortBy === 'openVulns' || sortBy === 'critVulns' || sortBy === 'sla';

    let prismaOrderBy: any = { createdAt: 'desc' };
    if (!isComputedSort && sortBy) {
       prismaOrderBy = { [sortBy]: sortDir || 'asc' };
    }

    // Fetch all if computed sort is requested, else fetch paginated
    const fetchLimit = isComputedSort ? undefined : limit;
    const fetchSkip = isComputedSort ? undefined : skip;

    const [data, total] = await this.prisma.$transaction([
      this.prisma.application.findMany({
        where,
        include: {
          owner: { select: { id: true, name: true, email: true, staffId: true, department: true } },
          securityRequests: {
            where: { deletedAt: null },
            include: {
              vulnerabilities: {
                where: { deletedAt: null },
                select: { id: true, severity: true, status: true, slaDueDate: true, reportedOn: true, shortDesc: true },
              },
            },
          },
        },
        skip: fetchSkip,
        take: fetchLimit,
        orderBy: prismaOrderBy,
      }),
      this.prisma.application.count({ where }),
    ]);

    let enriched = (data as Array<typeof data[0]>).map(app => {
      const allVulns = app.securityRequests?.flatMap((req: any) => req.vulnerabilities) || [];
      const openVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED').length;
      const critVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
      const vulnsWithSla = allVulns.filter((v: any) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v: any) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
      const scores = calculateApplicationScores(app as unknown as Parameters<typeof calculateApplicationScores>[0]);
      
      return {
        ...app,
        openVulnCount,
        critVulnCount,
        slaCompliancePct,
        openCvsFindingsCount: 0, 
        ...scores,
      };
    });

    if (isComputedSort) {
      enriched.sort((a, b) => {
        let valA = a.openVulnCount;
        let valB = b.openVulnCount;
        if (sortBy === 'critVulns') { valA = a.critVulnCount; valB = b.critVulnCount; }
        else if (sortBy === 'sla') { valA = a.slaCompliancePct; valB = b.slaCompliancePct; }
        
        return sortDir === 'asc' ? valA - valB : valB - valA;
      });
      enriched = enriched.slice(skip, skip + limit);
    }

    for (const app of enriched) {
      const cvsFindingsCount = await this.prisma.continuousScanFinding.count({
        where: { assetId: app.id, status: { not: 'PATCHED' } }
      });
      app.openCvsFindingsCount = cvsFindingsCount;
    }

    return { 
      data: enriched, 
      pagination: {
        page: Number(page), 
        pageSize: Number(limit), 
        totalItems: total, 
        totalPages: Math.ceil(total / limit) 
      }
    };
  }

  async aggregate(query: FilterApplicationDto) {
    const { 
      appId, name, type, department, ownerName, 
      vaptStatus, criticality, startDate, endDate, search 
    } = query;

    const where: any = { deletedAt: null };

    if (appId) where.appId = { contains: appId, mode: 'insensitive' };
    if (name) where.name = { contains: name, mode: 'insensitive' };
    if (type) where.type = type;
    if (department) where.department = { contains: department, mode: 'insensitive' };
    if (ownerName) {
      where.OR = [
        { owner: { name: { contains: ownerName, mode: 'insensitive' } } },
        { ownerEmail: { contains: ownerName, mode: 'insensitive' } },
      ];
    }
    if (vaptStatus) {
      if (vaptStatus === 'Overdue') where.vaptStatus = { in: ['Overdue', 'Critical'] };
      else where.vaptStatus = vaptStatus;
    }
    if (criticality) where.criticality = criticality;

    if (search) {
      const s = { contains: search, mode: 'insensitive' };
      const searchOr = [
        { appId: s },
        { name: s },
        { department: s },
        { ownerEmail: s },
        { owner: { name: s } },
      ];
      if (where.OR) {
        where.AND = [
          { OR: where.OR },
          { OR: searchOr }
        ];
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

    const data = await this.prisma.application.findMany({
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

    let critical = 0;
    let highRisk = 0;
    let totalSlaSum = 0;
    
    for (const app of data) {
      if (app.criticality === 'Critical') critical++;
      const allVulns = app.securityRequests?.flatMap((req: any) => req.vulnerabilities) || [];
      const openVulnCount = allVulns.filter((v: any) => v.status !== 'CLOSED').length;
      if (openVulnCount >= 10) highRisk++;
      
      const vulnsWithSla = allVulns.filter((v: any) => v.status !== 'CLOSED' && v.slaDueDate);
      const withinSla = vulnsWithSla.filter((v: any) => new Date(v.slaDueDate!) >= new Date()).length;
      const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
      totalSlaSum += slaCompliancePct;
    }

    return {
      total: data.length,
      critical,
      highRisk,
      avgSla: data.length > 0 ? Math.round(totalSlaSum / data.length) : 100
    };
  }

  async findOne(id: string) {
    const app = await this.prisma.application.findFirst({
      where: { id, deletedAt: null },
      include: {
        owner: { select: { id: true, name: true, email: true, staffId: true, department: true } },
        cloudResources: {
          include: { cloudResource: true },
        },
        infrastructureAssets: {
          include: { infrastructureAsset: { select: { id: true, serverId: true, serverName: true, environment: true, location: true } } },
        },
        securityRequests: {
          where: { deletedAt: null },
          orderBy: { initiatedOn: 'desc' },
          include: {
            initiatedBy: { select: { id: true, name: true, email: true } },
            assignedTo: { select: { id: true, name: true, email: true } },
            vulnerabilities: {
              where: { deletedAt: null },
              select: {
                id: true, vulnId: true, source: true, type: true, shortDesc: true,
                severity: true, cvss: true, status: true, pendingWith: true,
                reportedBy: true, reportedOn: true, slaDueDate: true, affectedComponent: true,
              },
            },
            comments: {
              orderBy: { createdAt: 'asc' },
              select: { id: true, body: true, authorName: true, authorRole: true, createdAt: true },
            },
          },
        },
      },
    });
    if (!app) throw new NotFoundException(`Application ${id} not found.`);

    const allVulns = app.securityRequests.flatMap(req => req.vulnerabilities);
    const openVulnCount = allVulns.filter(v => v.status !== 'CLOSED').length;
    const critVulnCount = allVulns.filter(v => v.status !== 'CLOSED' && (v.severity === 'CRITICAL' || v.severity === 'HIGH')).length;
    const vulnsWithSla = allVulns.filter(v => v.status !== 'CLOSED' && v.slaDueDate);
    const withinSla = vulnsWithSla.filter(v => new Date(v.slaDueDate!) >= new Date()).length;
    const slaCompliancePct = vulnsWithSla.length > 0 ? (withinSla / vulnsWithSla.length) * 100 : 100;
    
    const cvsFindingsCount = await this.prisma.continuousScanFinding.count({
      where: { assetId: id, status: { not: 'PATCHED' } }
    });

    const scores = calculateApplicationScores(app as unknown as Parameters<typeof calculateApplicationScores>[0]);

    const enriched = {
      ...app,
      openVulnCount,
      critVulnCount,
      slaCompliancePct,
      openCvsFindingsCount: cvsFindingsCount,
      ...scores,
    };

    return enriched;
  }

  private async logAudit(action: AuditAction, entityId: string, user: any, before: any = null, after: any = null) {
    if (!user) return;
    try {
      const fieldChanges: Record<string, { old: any; new: any }> = {};
      if (action === AuditAction.UPDATED && before && after) {
        const fieldsToTrack = [
          'name', 'ownerId', 'department', 'environment', 'criticality',
          'classification', 'vaptStatus', 'internetAccessible', 'piiData',
          'biaApp', 'prodUrl', 'preprodUrl', 'devUrl'
        ];
        
        for (const field of fieldsToTrack) {
          if (before[field] !== after[field]) {
            fieldChanges[field] = { old: before[field], new: after[field] };
          }
        }
      }

      await this.prisma.auditLog.create({
        data: {
          actorId: user.id,
          actorName: user.name || user.email,
          entityType: AuditEntityType.APPLICATION,
          entityId,
          action,
          before: before || undefined,
          after: after || undefined,
          metadata: {
            fieldChanges: Object.keys(fieldChanges).length > 0 ? fieldChanges : undefined,
            source: 'API'
          }
        }
      });
    } catch (err) {
      console.error('AuditLog failed:', err);
    }
  }

  async create(dto: CreateApplicationDto, user?: any) {
    const exists = await this.prisma.application.findFirst({
      where: { OR: [{ appId: dto.appId }, { name: dto.name }], deletedAt: null },
    });
    if (exists) throw new ConflictException('appId or name already exists.');

    const app = await this.prisma.application.create({ data: dto as unknown as Parameters<typeof this.prisma.application.create>[0]['data'] });
    await this.logAudit(AuditAction.CREATED, app.id, user, null, app);
    return app;
  }

  async update(id: string, dto: UpdateApplicationDto, user?: any) {
    const oldApp = await this.findOne(id);
    const newApp = await this.prisma.application.update({ where: { id }, data: dto as unknown as Parameters<typeof this.prisma.application.update>[0]['data'] });
    await this.logAudit(AuditAction.UPDATED, id, user, oldApp, newApp);
    return newApp;
  }

  async remove(id: string, user?: any) {
    const oldApp = await this.findOne(id);
    const newApp = await this.prisma.application.update({
      where: { id },
      data: { deletedAt: new Date() },
    });
    await this.logAudit(AuditAction.DELETED, id, user, oldApp, newApp);
    return { message: 'Application deleted.' };
  }
}
