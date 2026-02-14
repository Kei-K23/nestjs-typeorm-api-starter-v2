import {
  Injectable,
  BadRequestException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import * as crypto from 'crypto';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class TwoFactorService {
  private readonly logger = new Logger(TwoFactorService.name);

  constructor(
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
    private emailServiceUtils: EmailServiceUtils,
    private configService: ConfigService,
  ) {}

  async enableTwoFactor(userId: string, email: string): Promise<void> {
    const user = await this.adminRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    if (user.email !== email) {
      throw new BadRequestException('Email does not match user account');
    }

    // Generate verification code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create cache key record
    const cacheKey = this.cacheKeyRepository.create({
      adminId: userId,
      service: CacheKeyService.TWO_FACTOR,
      code,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });
    await this.cacheKeyRepository.save(cacheKey);

    // Send verification email
    await this.emailServiceUtils.sendTwoFactorCode({
      email,
      code,
      userName: user.fullName || user.email,
      fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
      expiresIn: 10,
    });

    this.logger.log(`2FA verification code sent to user ${userId}`);
  }

  async verifyTwoFactor(userId: string, code: string): Promise<boolean> {
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: {
        adminId: userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.PENDING,
      },
      order: { createdAt: 'DESC' },
    });

    if (!cacheKey) {
      throw new BadRequestException(
        'No pending two-factor authentication code found',
      );
    }

    // Check if code has expired
    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      throw new BadRequestException('Verification code has expired');
    }

    // Check if max attempts reached
    if (cacheKey.attempts >= cacheKey.maxAttempts) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    cacheKey.attempts += 1;

    // Verify code
    if (cacheKey.code !== code) {
      await this.cacheKeyRepository.save(cacheKey);
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as active
    cacheKey.status = CacheKeyStatus.VERIFIED;
    await this.cacheKeyRepository.save(cacheKey);

    // Update user's 2FA status
    await this.adminRepository.update(userId, { twoFactorEnabled: true });

    this.logger.log(`2FA enabled for user ${userId}`);
    return true;
  }

  async disableTwoFactor(userId: string, password: string): Promise<void> {
    const user = await this.adminRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Verify password (you'll need to implement password verification)
    if (!password) {
      throw new BadRequestException('Password is required to disable 2FA');
    }
    if (!(await bcrypt.compare(password, user.password))) {
      throw new UnauthorizedException('Password does not match');
    }

    // Deactivate all active cache key records
    await this.cacheKeyRepository.update(
      {
        adminId: userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.VERIFIED,
      },
      { status: CacheKeyStatus.EXPIRED },
    );

    // Update user's 2FA status
    await this.adminRepository.update(userId, { twoFactorEnabled: false });

    this.logger.log(`2FA disabled for user ${userId}`);
  }

  async sendVerificationCode(userId: string): Promise<void> {
    const user = await this.adminRepository.findOne({ where: { id: userId } });
    if (!user) {
      throw new BadRequestException('User not found');
    }

    // Check if there's an active 2FA setup
    const existing = await this.cacheKeyRepository.findOne({
      where: {
        adminId: userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.VERIFIED,
      },
    });

    if (existing) {
      throw new BadRequestException(
        'Two-factor verification code is already sent',
      );
    }

    // Generate new verification code
    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

    // Create new verification record
    const cacheKey = this.cacheKeyRepository.create({
      adminId: userId,
      service: CacheKeyService.TWO_FACTOR,
      code,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });

    await this.cacheKeyRepository.save(cacheKey);

    // Send verification email
    await this.emailServiceUtils.sendTwoFactorCode({
      code,
      email: user.email,
      userName: user.fullName || user.email,
      fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
      expiresIn: 10,
    });

    this.logger.log(`2FA verification code sent to user ${userId}`);
  }

  async validateLoginCode(userId: string, code: string): Promise<boolean> {
    const cacheKey = await this.cacheKeyRepository.findOne({
      where: {
        adminId: userId,
        service: CacheKeyService.TWO_FACTOR,
        status: CacheKeyStatus.PENDING,
        code,
      },
    });

    if (!cacheKey) {
      return false;
    }

    // Check if code has expired
    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    // Check if max attempts reached
    if (cacheKey.attempts >= cacheKey.maxAttempts) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    // Check if code has expired
    if (new Date() > cacheKey.expiresAt) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    // Check if max attempts reached
    if (cacheKey.attempts >= cacheKey.maxAttempts) {
      cacheKey.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    // Increment attempts
    cacheKey.attempts += 1;

    // Verify code
    if (cacheKey.code !== code) {
      await this.cacheKeyRepository.save(cacheKey);
      return false;
    }

    // Mark as used
    cacheKey.status = CacheKeyStatus.USED;
    await this.cacheKeyRepository.save(cacheKey);

    return true;
  }

  async isTwoFactorEnabled(userId: string): Promise<boolean> {
    const user = await this.adminRepository.findOne({ where: { id: userId } });
    return user?.twoFactorEnabled || false;
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
