import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../services/auth.service';
import { AuthenticatedUser, JwtPayload } from '../interfaces/user.interface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_SECRET')!,
    });
  }

  async validate(payload: JwtPayload): Promise<AuthenticatedUser> {
    if (payload.subjectType === 'ADMIN' && payload.adminId) {
      const admin = await this.authService.validateAdminById(payload.adminId);
      if (!admin) {
        throw new UnauthorizedException('Invalid token');
      }
      const { password, ...adminWithoutPassword } = admin;
      void password;
      return {
        ...adminWithoutPassword,
        subjectType: 'ADMIN',
      };
    }

    if (payload.subjectType === 'USER' && payload.userId) {
      const user = await this.authService.validateUserById(payload.userId);
      if (!user) {
        throw new UnauthorizedException('Invalid token');
      }
      const { password, ...userWithoutPassword } = user;
      void password;
      return {
        ...userWithoutPassword,
        subjectType: 'USER',
      };
    }

    throw new UnauthorizedException('Invalid token');
  }
}
