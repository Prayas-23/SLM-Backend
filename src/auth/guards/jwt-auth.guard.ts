import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Protects routes with a valid JWT Bearer token.
 * Attach to any route or controller that requires authentication.
 *
 * @example
 * @UseGuards(JwtAuthGuard)
 * @Get('profile')
 * getProfile(@Request() req) { return req.user; }
 */
// @Injectable()
// export class JwtAuthGuard extends AuthGuard('jwt') {}

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
    canActivate(context: any) {
        console.log('JWT GUARD HIT');
        return super.canActivate(context);
    }
}
