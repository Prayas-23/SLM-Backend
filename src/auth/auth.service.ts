import {
  Injectable,
  UnauthorizedException,
  ForbiddenException,
  BadRequestException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { PasswordService } from '../common/services/password.service';
import { LoginDto } from './dto/login.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { SettingsCacheService } from '../settings-cache/settings-cache.service';

// Max failed attempts loaded from DB dynamically

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly passwordService: PasswordService,
    private readonly settingsCache: SettingsCacheService,
  ) {}

  // ─── Login ────────────────────────────────────────────────────────────────

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findFirst({
      where: { email: dto.email, deletedAt: null },
    });

    // Generic message — do not reveal whether email exists
    if (!user) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    // Account lockout check
    if (!user.isActive) {
      throw new ForbiddenException(
        'Your account has been locked due to too many failed login attempts. Contact your administrator.',
      );
    }

    const passwordValid = await this.passwordService.compare(
      dto.password,
      user.passwordHash,
    );

    if (!passwordValid) {
      await this.handleFailedAttempt(user.id);
      throw new UnauthorizedException('Invalid credentials.');
    }

    // Successful login — reset counters and record timestamp
    await this.prisma.user.update({
      where: { id: user.id },
      data: {
        lastLoginAt: new Date(),
      },
    });

    const expiresIn = this.settingsCache.get('security.jwtExpiry', '1h');

    const token = await this.signToken(user.id, user.email, user.role, expiresIn);

    return {
      accessToken: token,
      tokenType: 'Bearer',
      expiresIn: expiresIn,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        department: user.department,
        avatarUrl: user.avatarUrl,
      },
    };
  }

  // ─── Profile ──────────────────────────────────────────────────────────────

  async getProfile(userId: string) {
    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        department: true,
        staffId: true,
        avatarUrl: true,
        lastLoginAt: true,
        createdAt: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    return user;
  }

  // ─── Change Password ──────────────────────────────────────────────────────

  async changePassword(userId: string, dto: ChangePasswordDto) {
    if (dto.newPassword !== dto.confirmPassword) {
      throw new BadRequestException(
        'New password and confirm password do not match.',
      );
    }

    const user = await this.prisma.user.findFirst({
      where: { id: userId, deletedAt: null },
    });

    if (!user) {
      throw new UnauthorizedException('User not found.');
    }

    const currentValid = await this.passwordService.compare(
      dto.currentPassword,
      user.passwordHash,
    );

    if (!currentValid) {
      throw new UnauthorizedException('Current password is incorrect.');
    }

    const newHash = await this.passwordService.hash(dto.newPassword);

    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash: newHash },
    });

    return { message: 'Password changed successfully.' };
  }

  // ─── Logout ───────────────────────────────────────────────────────────────
  // JWT-only MVP: logout is stateless — client discards the token.
  // No server-side token blacklist in MVP scope.

  async logout() {
    return { message: 'Logged out successfully. Please discard your token.' };
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────

  private async signToken(userId: string, email: string, role: string, expiresIn: string): Promise<string> {
    return this.jwtService.sign({
      sub: userId,
      email,
      role,
    }, { expiresIn: expiresIn as unknown as number });
  }

  private async handleFailedAttempt(userId: string): Promise<void> {
    // Read current state
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, isActive: true },
    });

    if (!user) return;

    // Count failed attempts from audit log
    const failedCount = await this.prisma.auditLog.count({
      where: {
        entityType: 'USER',
        entityId: userId,
        action: 'UPDATED',
        metadata: { path: ['event'], equals: 'LOGIN_FAILED' },
      },
    });

    // Log this failed attempt
    await this.prisma.auditLog.create({
      data: {
        entityType: 'USER',
        entityId: userId,
        action: 'UPDATED',
        metadata: { event: 'LOGIN_FAILED', attemptNumber: failedCount + 1 },
      },
    });

    // Fetch dynamic max failed attempts
    const maxFailedAttempts = this.settingsCache.getNumber('security.maxLoginAttempts', 5);

    // Lock account after maxFailedAttempts
    if (failedCount + 1 >= maxFailedAttempts) {
      await this.prisma.user.update({
        where: { id: userId },
        data: { isActive: false },
      });

      await this.prisma.auditLog.create({
        data: {
          entityType: 'USER',
          entityId: userId,
          action: 'UPDATED',
          metadata: { event: 'ACCOUNT_LOCKED', reason: 'MAX_FAILED_ATTEMPTS' },
        },
      });
    }
  }
}
