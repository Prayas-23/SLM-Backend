import { Injectable, NotFoundException, ConflictException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { CreateCloudAccountDto, UpdateCloudAccountDto, FilterCloudAccountDto } from './dto/cloud-account.dto';

@Injectable()
export class CloudAccountsService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(query: FilterCloudAccountDto) {
    const { page = 1, limit = 20, environment, search } = query;
    const skip = (page - 1) * limit;
    const where: any = { deletedAt: null };
    if (environment) where.environment = environment;
    if (search) {
      where.OR = [
        { accountId: { contains: search, mode: 'insensitive' } },
        { extId: { contains: search, mode: 'insensitive' } },
        { label: { contains: search, mode: 'insensitive' } },
      ];
    }

    const [data, total] = await this.prisma.$transaction([
      this.prisma.cloudAccount.findMany({
        where,
        include: {
          cloudResources: {
            where: { deletedAt: null },
            take: 5,
            include: {
              applications: {
                include: { application: { select: { id: true, appId: true, name: true } } },
              },
            },
          },
        },
        skip, take: limit, orderBy: { createdAt: 'desc' },
      }),
      this.prisma.cloudAccount.count({ where }),
    ]);

    // Aggregate linked apps per account from cloudResources
    const enriched = data.map((account) => {
      const appMap = new Map<string, { id: string; name: string }>();
      for (const res of account.cloudResources) {
        for (const link of (res as unknown as { applications?: Array<{ application?: { id: string; name: string } }> }).applications ?? []) {
          const app = link.application;
          if (app && !appMap.has(app.id)) appMap.set(app.id, { id: app.id, name: app.name });
        }
      }
      return { ...account, apps: Array.from(appMap.values()) };
    });

    return { data: enriched, total, page, limit, totalPages: Math.ceil(total / limit) };
  }

  async findOne(id: string) {
    const account = await this.prisma.cloudAccount.findFirst({
      where: { id, deletedAt: null },
      include: {
        cloudResources: {
          where: { deletedAt: null },
          include: {
            applications: {
              include: { application: { select: { id: true, appId: true, name: true } } },
            },
          },
        },
      },
    });
    if (!account) throw new NotFoundException(`Cloud account ${id} not found.`);

    // Aggregate linked apps
    const appMap = new Map<string, { id: string; name: string }>();
    for (const res of account.cloudResources) {
      for (const link of (res as unknown as { applications?: Array<{ application?: { id: string; name: string } }> }).applications ?? []) {
        const app = link.application;
        if (app && !appMap.has(app.id)) appMap.set(app.id, { id: app.id, name: app.name });
      }
    }
    return { ...account, apps: Array.from(appMap.values()) };
  }

  async create(dto: CreateCloudAccountDto) {
    const exists = await this.prisma.cloudAccount.findFirst({
      where: { accountId: dto.accountId, deletedAt: null },
    });
    if (exists) throw new ConflictException('accountId already exists.');
    return this.prisma.cloudAccount.create({ data: dto as unknown as Parameters<typeof this.prisma.cloudAccount.create>[0]['data'] });
  }

  async update(id: string, dto: UpdateCloudAccountDto) {
    await this.findOne(id);
    return this.prisma.cloudAccount.update({ where: { id }, data: dto as unknown as Parameters<typeof this.prisma.cloudAccount.update>[0]['data'] });
  }

  async remove(id: string) {
    await this.findOne(id);
    await this.prisma.cloudAccount.update({ where: { id }, data: { deletedAt: new Date() } });
    return { message: 'Cloud account deleted.' };
  }
}
