import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { RegisterDto } from './dto/create-auth.dto';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { LoginDto } from './dto/login.dto';

type Tokens = { accessToken: string; refreshToken: string };

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async register(dto: RegisterDto) {
    const existing = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true },
    });

    if (existing) {
      throw new BadRequestException('Email already in use');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);

    const user = await this.prisma.user.create({
      data: {
        name: dto.name,
        email: dto.email,
        password: hashedPassword,
        role: 'USER',
      },
      select: {
        id: true,
        name: true,
        email: true,
        role: true,
        createdAt: true,
      },
    });
    return {
      message: 'User created successfully',
      user,
    };
  }

  private async signTokens(userId: string, email: string): Promise<Tokens> {
    const accessSecret = this.config.get<string>('JWT_ACCESS_SECRET');
    const refreshSecret = this.config.get<string>('JWT_REFRESH_SECRET');

    if (!accessSecret || !refreshSecret) {
      throw new Error('JWT secrets are missing in .env');
    }

    const payload = { sub: userId, email };

    const [accessToken, refreshToken] = await Promise.all([
      this.jwt.signAsync(payload, { secret: accessSecret, expiresIn: '15m' }),
      this.jwt.signAsync(payload, { secret: refreshSecret, expiresIn: '7d' }),
    ]);

    return { accessToken, refreshToken };
  }

  async login(dto: LoginDto) {
    const user = await this.prisma.user.findUnique({
      where: { email: dto.email },
      select: { id: true, email: true, password: true, name: true, role: true },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const ok = await bcrypt.compare(dto.password, user.password);

    if (!ok) {
      throw new UnauthorizedException('Invalid email or password');
    }

    const tokens = await this.signTokens(user.id, user.email);

    return {
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
    };
  }

  async refreshFromToken(refreshToken: string) {
    const refreshSecret = this.config.get<string>('JWT_REFRESH_SECRET');
    if (!refreshSecret) throw new Error('JWT_REFRESH_SECRET missing');

    // Verify refresh token signature + extract payload
    let payload: { sub: string; email: string };
    try {
      payload = await this.jwt.verifyAsync(refreshToken, {
        secret: refreshSecret,
      });
    } catch {
      throw new UnauthorizedException('Invalid refresh token');
    }

    // Optional: ensure user still exists (recommended)
    const user = await this.prisma.user.findUnique({
      where: { id: payload.sub },
      select: { id: true, email: true, name: true, role: true },
    });
    if (!user) throw new UnauthorizedException('User not found');

    const tokens = await this.signTokens(user.id, user.email);

    return {
      user,
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken, // controller will rotate cookie
    };
  }
}
