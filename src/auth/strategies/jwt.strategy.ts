import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';

export interface JwtPayload {
  sub: string;   // userId
  email: string;
  role: string;
}

/**
 * Passport JWT strategy.
 * Validates the token, then loads the live user from DB to ensure
 * account is still active and not deleted.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    console.log('JWT STRATEGY CONSTRUCTOR CALLED');
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('JWT_SECRET'),
    });
  }

  async validate(payload: JwtPayload) {
    console.log('========== JWT VALIDATE ==========');
    console.log('Payload:', payload);

    const user = await this.prisma.user.findFirst({
      where: {
        id: payload.sub,
        isActive: true,
        deletedAt: null,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        department: true,
        staffId: true,
        avatarUrl: true,
      },
    });

    if (!user) {
      throw new UnauthorizedException('User account is inactive or not found.');
    }

    return user; // attached to req.user
  }
}
