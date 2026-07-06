import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  CreateCloudResourceDto,
  UpdateCloudResourceDto,
  LinkAppCloudResourceDto,
  FilterCloudResourceDto,
} from './dto/cloud-resource.dto';

@Injectable()
export class CloudResourcesService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(query: FilterCloudResourceDto) {
    const { 
      page = 1, limit = 20, environment, startDate, endDate,
      search, resourceId, resourceExtId, resourceName, type,
      technologyName, stackLayer, cloudProvider, cloudAccountId,
      cloudAccountExtId, cloudAccountProvider, status, region,
      sortBy, sortDir
    } = query;
    const skip = (page - 1) * limit;
    
    const where: any = { deletedAt: null };
    if (environment) where.environment = environment;
    if (resourceId) where.resourceId = { contains: resourceId, mode: 'insensitive' };
    if (resourceExtId) where.resourceExtId = { contains: resourceExtId, mode: 'insensitive' };
    if (resourceName) where.resourceName = { contains: resourceName, mode: 'insensitive' };
    if (type) where.type = type;
    if (technologyName) where.technologyName = { contains: technologyName, mode: 'insensitive' };
    if (stackLayer) where.stackLayer = stackLayer;
    if (cloudProvider) where.cloudProvider = cloudProvider;
    if (status) where.status = { contains: status, mode: 'insensitive' };
    if (region) where.region = { contains: region, mode: 'insensitive' };

    // Relations filter
    if (cloudAccountId || cloudAccountExtId || cloudAccountProvider) {
      where.cloudAccount = {};
      if (cloudAccountId) where.cloudAccount.accountId = { contains: cloudAccountId, mode: 'insensitive' };
      if (cloudAccountExtId) where.cloudAccount.extId = { contains: cloudAccountExtId, mode: 'insensitive' };
      if (cloudAccountProvider) where.cloudAccount.provider = cloudAccountProvider;
    }

    if (search) {
      where.OR = [
        { resourceId: { contains: search, mode: 'insensitive' } },
        { resourceExtId: { contains: search, mode: 'insensitive' } },
        { resourceName: { contains: search, mode: 'insensitive' } },
        { technologyName: { contains: search, mode: 'insensitive' } },
        { cloudAccount: { accountId: { contains: search, mode: 'insensitive' } } },
        { cloudAccount: { extId: { contains: search, mode: 'insensitive' } } },
        { status: { contains: search, mode: 'insensitive' } },
        { region: { contains: search, mode: 'insensitive' } },
      ];
    }
    
    if (startDate || endDate) {
      where.createdAt = {};
      if (startDate) where.createdAt.gte = new Date(startDate);
      if (endDate) where.createdAt.lte = new Date(endDate);
    }
    
    let orderBy: any = { createdAt: 'desc' };
    if (sortBy) {
      orderBy = { [sortBy]: sortDir || 'asc' };
    }

    const [data, total] = await this.prisma.$transaction([
      this.prisma.cloudResource.findMany({
        where,
        include: {
          cloudAccount: { select: { id: true, accountId: true, extId: true, provider: true, label: true } },
          infraAsset: { select: { id: true, serverId: true, serverName: true } },
        },
        skip, take: limit,
        orderBy,
      }),
      this.prisma.cloudResource.count({ where }),
    ]);

    return { data, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async findOne(id: string) {
    const resource = await this.prisma.cloudResource.findFirst({
      where: { id, deletedAt: null },
      include: {
        cloudAccount: true,
        infraAsset: true,
        applications: { include: { application: { select: { id: true, appId: true, name: true } } } },
      },
    });
    if (!resource) throw new NotFoundException(`Cloud resource ${id} not found.`);
    return resource;
  }

  async create(dto: CreateCloudResourceDto) {
    const exists = await this.prisma.cloudResource.findFirst({
      where: { resourceId: dto.resourceId, deletedAt: null },
    });
    if (exists) throw new ConflictException('resourceId already exists.');
    return this.prisma.cloudResource.create({ data: dto as unknown as Parameters<typeof this.prisma.cloudResource.create>[0]['data'] });
  }

  async update(id: string, dto: UpdateCloudResourceDto) {
    await this.findOne(id);
    return this.prisma.cloudResource.update({ where: { id }, data: dto as unknown as Parameters<typeof this.prisma.cloudResource.update>[0]['data'] });
  }

  async remove(id: string) {
    await this.findOne(id);
    await this.prisma.cloudResource.update({ where: { id }, data: { deletedAt: new Date() } });
    return { message: 'Cloud resource deleted.' };
  }

  // ── M2M: link / unlink application ───────────────────────────────────────

  async linkApplication(id: string, dto: LinkAppCloudResourceDto) {
    await this.findOne(id);
    try {
      await this.prisma.appCloudResource.create({
        data: { cloudResourceId: id, applicationId: dto.applicationId },
      });
    } catch {
      throw new ConflictException('Application is already linked to this cloud resource.');
    }
    return { message: 'Application linked to cloud resource.' };
  }

  async unlinkApplication(id: string, applicationId: string) {
    const link = await this.prisma.appCloudResource.findFirst({
      where: { cloudResourceId: id, applicationId },
    });
    if (!link) throw new NotFoundException('Link not found.');
    await this.prisma.appCloudResource.delete({ where: { id: link.id } });
    return { message: 'Application unlinked from cloud resource.' };
  }
}
