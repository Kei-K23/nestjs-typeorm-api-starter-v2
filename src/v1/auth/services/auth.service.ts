import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  Logger,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import { User } from 'src/v1/user/entities/user.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { JwtPayload } from '../interfaces/user.interface';
import {
  ActivityAction,
  UserActivityLog,
} from 'src/v1/activity-log/entities/user-activity-log.entity';
import { Request } from 'express';
import { parseUserAgent } from 'src/common/utils/user-agent.util';
import { TwoFactorService } from './two-factor.service';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { UserLoginDto } from '../dto/user-login.dto';
import { UpdateProfileDto } from '../dto/update-profile.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { ForgotPasswordSendOTPDto } from '../dto/forgot-password-send-otp.dto';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import * as crypto from 'crypto';
import {
  CacheKey,
  CacheKeyService,
  CacheKeyStatus,
} from '../entities/cache-key.entity';
import { VerifyPasswordResetOTPCodeDto } from '../dto/verify-password-reset-otp-code.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
    @InjectRepository(RefreshToken)
    private refreshTokenRepository: Repository<RefreshToken>,
    @InjectRepository(UserActivityLog)
    private userActivityLogRepository: Repository<UserActivityLog>,
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
    private emailServiceUtils: EmailServiceUtils,
  ) {}

  async validateAdmin(email: string, plainPassword: string) {
    const admin = await this.adminRepository.findOne({
      where: { email },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
        'role.rolePermissions.permission.module',
      ],
    });

    if (!admin) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!(await bcrypt.compare(plainPassword, admin.password))) {
      throw new UnauthorizedException('Invalid password');
    }
    const { password, ...result } = admin;
    void password;
    return result;
  }

  async validateAdminById(id: string): Promise<Admin | null> {
    return this.adminRepository.findOne({
      where: { id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
        'role.rolePermissions.permission.module',
      ],
    });
  }

  async validateUserById(id: string): Promise<User | null> {
    return this.userRepository.findOne({
      where: { id },
    });
  }

  async userLogin(loginDto: UserLoginDto, request: Request) {
    const user = await this.userRepository.findOne({
      where: { phone: loginDto.phone },
    });

    if (!user || !user.password) {
      this.logger.warn(
        `Invalid login attempt for phone '${loginDto.phone}' (user not found or no password)`,
      );
      throw new UnauthorizedException('Invalid phone or password');
    }

    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      this.logger.warn(
        `Invalid login attempt for phone '${loginDto.phone}' (incorrect password)`,
      );
      throw new UnauthorizedException('Invalid phone or password');
    }

    if (user.isBanned) {
      this.logger.warn(`Banned user with ID '${user.id}' attempted to login`);
      throw new UnauthorizedException('Your account has been banned');
    }

    const payload: JwtPayload = {
      sub: user.id,
      subjectType: 'USER',
      userId: user.id,
    };

    const accessToken = this.jwtService.sign(payload);

    await this.revokeAllUserTokens(user.id);
    const refreshToken = await this.generateRefreshToken(user.id);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      isActivityLog: true,
      action: ActivityAction.LOGIN,
      description: 'User logged in successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    this.logger.log(`User with ID '${user.id}' logged in successfully`);
    await this.userActivityLogRepository.save(userActivityLog);

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        172800000,
      ),
      refreshTokenExpiresAt: this.configService.get<number>(
        'JWT_REFRESH_EXPIRATION',
        2592000000,
      ),
      user: {
        id: user.id,
      },
    };
  }

  async adminLogin(loginDto: AdminLoginDto, request: Request) {
    const admin = await this.validateAdmin(loginDto.email, loginDto.password);

    // Check if 2FA is enabled for this user
    const is2FAEnabled = await this.twoFactorService.isTwoFactorEnabled(
      admin.id,
    );

    if (is2FAEnabled) {
      await this.twoFactorService.sendVerificationCode(admin.id);

      return {
        requiresTwoFactor: true,
        userId: admin.id,
        message: 'Two-factor authentication code sent to your email',
      };
    }

    const fullAdmin = await this.adminRepository.findOne({
      where: { id: admin.id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
        'role.rolePermissions.permission.module',
      ],
    });

    if (!fullAdmin) {
      this.logger.warn(`Admin with ID '${admin.id}' not found`);
      throw new UnauthorizedException(`Admin with ID '${admin.id}' not found`);
    }

    return this.completeAdminLogin(fullAdmin, request);
  }

  async verifyTwoFactorAndLogin(
    userId: string,
    code: string,
    request: Request,
  ) {
    // Validate the 2FA code
    const isValidCode = await this.twoFactorService.validateLoginCode(
      userId,
      code,
    );

    if (!isValidCode) {
      this.logger.warn(
        `Invalid or expired verification code for user with ID '${userId}'`,
      );
      throw new UnauthorizedException(
        `Invalid or expired verification code for user with ID '${userId}'`,
      );
    }

    const admin = await this.adminRepository.findOne({
      where: { id: userId },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
        'role.rolePermissions.permission.module',
      ],
    });

    if (!admin) {
      this.logger.warn(`Admin with ID '${userId}' not found`);
      throw new UnauthorizedException(`Admin with ID '${userId}' not found`);
    }

    // Complete the login process
    return this.completeAdminLogin(admin, request);
  }

  private async completeAdminLogin(admin: Admin, request: Request) {
    const payload: JwtPayload = {
      sub: admin.id,
      subjectType: 'ADMIN',
      adminId: admin.id,
      roleId: admin.role.id,
    };

    const accessToken = this.jwtService.sign(payload);
    await this.revokeAllAdminTokens(admin.id);

    const refreshToken = await this.generateAdminRefreshToken(admin.id);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      adminId: admin.id,
      isActivityLog: true,
      action: ActivityAction.LOGIN,
      description: `Admin logged in successfully`,
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    await this.adminRepository.update(admin.id, {
      lastLoginAt: new Date().toISOString(),
    });

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        172800000,
      ),
      refreshTokenExpiresAt: this.configService.get<number>(
        'JWT_REFRESH_EXPIRATION',
        2592000000,
      ),
      user: {
        id: admin.id,
      },
    };
  }

  async refreshAccessToken(refreshTokenString: string) {
    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshTokenString, isRevoked: false },
      relations: [
        'user',
        'admin',
        'admin.role',
        'admin.role.rolePermissions',
        'admin.role.rolePermissions.permission',
        'admin.role.rolePermissions.permission.module',
      ],
    });

    if (!refreshToken) {
      this.logger.warn(
        `Invalid refresh token '${refreshTokenString}' provided`,
      );
      throw new UnauthorizedException(
        `Invalid refresh token '${refreshTokenString}' provided`,
      );
    }

    const now = new Date();

    if (refreshToken.expiresAt < now) {
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);

      const ownerId = refreshToken.admin?.id ?? refreshToken.user?.id;

      throw new UnauthorizedException(
        ownerId
          ? `Expired refresh token for user with ID '${ownerId}'! Please login again`
          : 'Expired refresh token! Please login again',
      );
    }

    if (!refreshToken.admin && !refreshToken.user) {
      throw new UnauthorizedException('Invalid refresh token owner');
    }

    let payload: JwtPayload;
    let ownerId: string;

    if (refreshToken.admin) {
      payload = {
        sub: refreshToken.admin.id,
        subjectType: 'ADMIN',
        adminId: refreshToken.admin.id,
        roleId: refreshToken.admin.role?.id,
      };
      ownerId = refreshToken.admin.id;
    } else {
      payload = {
        sub: refreshToken.user.id,
        subjectType: 'USER',
        userId: refreshToken.user.id,
      };
      ownerId = refreshToken.user.id;
    }

    const accessToken = this.jwtService.sign(payload);
    this.logger.log(`User with ID '${ownerId}' logged in successfully`);

    return {
      accessToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        172800000,
      ),
      user: {
        id: ownerId,
      },
    };
  }

  async logout(refreshTokenString: string) {
    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: refreshTokenString },
    });

    if (refreshToken) {
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);
    }
  }

  async revokeAllUserTokens(userId: string) {
    await this.refreshTokenRepository.update(
      { userId, isRevoked: false },
      { isRevoked: true },
    );
  }

  async revokeAllAdminTokens(adminId: string) {
    await this.refreshTokenRepository.update(
      { adminId, isRevoked: false },
      { isRevoked: true },
    );
  }

  private async generateRefreshToken(userId: string): Promise<string> {
    const token = this.jwtService.sign(
      { sub: userId },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<number>(
          'JWT_REFRESH_EXPIRATION',
          2592000000,
        ),
      },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    const refreshToken = this.refreshTokenRepository.create({
      token,
      userId,
      expiresAt,
    });

    await this.refreshTokenRepository.save(refreshToken);
    return token;
  }

  private async generateAdminRefreshToken(adminId: string): Promise<string> {
    const token = this.jwtService.sign(
      { sub: adminId },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<number>(
          'JWT_REFRESH_EXPIRATION',
          2592000000,
        ),
      },
    );

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    const refreshToken = this.refreshTokenRepository.create({
      token,
      adminId,
      expiresAt,
    });

    await this.refreshTokenRepository.save(refreshToken);
    return token;
  }

  async updateProfile(
    userId: string,
    subjectType: 'ADMIN' | 'USER' | undefined,
    updateProfileDto: UpdateProfileDto,
    request: Request,
  ) {
    if (subjectType === 'ADMIN') {
      const admin = await this.adminRepository.findOne({
        where: { id: userId },
      });

      if (!admin) {
        this.logger.warn(`Admin with ID '${userId}' not found`);
        throw new NotFoundException(`Admin with ID '${userId}' not found`);
      }

      if (
        updateProfileDto.profileImageUrl &&
        updateProfileDto.profileImageUrl !== admin.profileImageUrl
      ) {
        if (
          admin.profileImageUrl &&
          (await this.s3ClientUtils.objectExists(admin.profileImageUrl))
        ) {
          await this.s3ClientUtils.deleteObject(admin.profileImageUrl);
        }
      }

      const updatedAdmin = this.adminRepository.merge(admin, {
        fullName:
          updateProfileDto.fullName !== undefined
            ? updateProfileDto.fullName
            : admin.fullName,
        email:
          updateProfileDto.email !== undefined
            ? updateProfileDto.email
            : admin.email,
        phone:
          updateProfileDto.phone !== undefined
            ? updateProfileDto.phone
            : admin.phone,
        dateOfBirth:
          updateProfileDto.dateOfBirth !== undefined
            ? updateProfileDto.dateOfBirth
            : admin.dateOfBirth,
        gender:
          updateProfileDto.gender !== undefined
            ? updateProfileDto.gender
            : admin.gender,
        profileImageUrl:
          updateProfileDto.profileImageUrl !== undefined
            ? updateProfileDto.profileImageUrl
            : admin.profileImageUrl,
      });

      if (updateProfileDto.password) {
        updatedAdmin.password = updateProfileDto.password;
      }

      const savedAdmin = await this.adminRepository.save(updatedAdmin);

      const { device, browser, os } = parseUserAgent(request);
      const userActivityLog = this.userActivityLogRepository.create({
        adminId: admin.id,
        action: ActivityAction.UPDATE,
        description: 'Admin profile updated successfully',
        ipAddress: request?.ip,
        userAgent: request?.headers['user-agent'],
        device,
        browser,
        os,
        location: request?.headers['cf-ipcountry'] as string,
      });
      await this.userActivityLogRepository.save(userActivityLog);

      const { password, ...result } = savedAdmin;
      void password;

      this.logger.log(
        `Admin with ID '${admin.id}' profile updated successfully`,
      );
      return result;
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    if (
      updateProfileDto.profileImageUrl &&
      updateProfileDto.profileImageUrl !== user.profileImageUrl
    ) {
      if (
        user.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(user.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(user.profileImageUrl);
      }
    }

    const updatedUser = await this.userRepository.preload({
      id: userId,
      ...updateProfileDto,
    });
    if (!updatedUser) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new BadRequestException(`User with ID '${userId}' not found`);
    }

    if (updateProfileDto.password) {
      updatedUser.password = updateProfileDto.password;
    }

    const savedUser = await this.userRepository.save(updatedUser);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.UPDATE,
      description: 'User profile updated successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    const { password, ...result } = savedUser;
    void password;

    this.logger.log(`User with ID '${user.id}' profile updated successfully`);
    return result;
  }

  async changePassword(
    userId: string,
    subjectType: 'ADMIN' | 'USER' | undefined,
    changePasswordDto: ChangePasswordDto,
    request: Request,
  ): Promise<void> {
    if (subjectType === 'ADMIN') {
      const admin = await this.adminRepository.findOne({
        where: { id: userId },
      });

      if (!admin) {
        this.logger.warn(`Admin with ID '${userId}' not found`);
        throw new NotFoundException(`Admin with ID '${userId}' not found`);
      }

      const isCurrentPasswordValid = await bcrypt.compare(
        changePasswordDto.currentPassword,
        admin.password,
      );

      if (!isCurrentPasswordValid) {
        this.logger.warn(
          `Admin with ID '${userId}' provided incorrect current password`,
        );
        throw new BadRequestException(`Incorrect current password`);
      }

      admin.password = changePasswordDto.newPassword;
      await this.adminRepository.save(admin);

      await this.revokeAllAdminTokens(userId);

      const { device, browser, os } = parseUserAgent(request);
      const userActivityLog = this.userActivityLogRepository.create({
        adminId: admin.id,
        action: ActivityAction.UPDATE,
        description: 'Admin password changed successfully',
        ipAddress: request?.ip,
        userAgent: request?.headers['user-agent'],
        device,
        browser,
        os,
        location: request?.headers['cf-ipcountry'] as string,
      });

      this.logger.log(
        `Admin with ID '${admin.id}' password changed successfully`,
      );
      await this.userActivityLogRepository.save(userActivityLog);

      return;
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    const isCurrentPasswordValid = await bcrypt.compare(
      changePasswordDto.currentPassword,
      user.password,
    );

    if (!isCurrentPasswordValid) {
      this.logger.warn(
        `User with ID '${userId}' provided incorrect current password`,
      );
      throw new BadRequestException(`Incorrect current password`);
    }

    user.password = changePasswordDto.newPassword;
    await this.userRepository.save(user);

    await this.revokeAllUserTokens(userId);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.UPDATE,
      description: 'User password changed successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });

    this.logger.log(`User with ID '${user.id}' password changed successfully`);
    await this.userActivityLogRepository.save(userActivityLog);
  }

  async deleteProfile(userId: string, request: Request): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['refreshTokens', 'twoFactorAuth'],
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    // Log activity before deletion
    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.DELETE,
      description: 'User account deleted successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    // Revoke all refresh tokens
    await this.revokeAllUserTokens(userId);

    // Delete user profile image from S3 if it exists
    if (user.profileImageUrl) {
      if (
        user.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(user.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(user.profileImageUrl);
      }
    }

    // Soft delete user
    this.logger.log(
      `User with ID '${user.id}' account soft deleted successfully`,
    );
    await this.userRepository.softRemove(user);
  }

  async passwordResetOTPSend(
    forgotPasswordSendOTP: ForgotPasswordSendOTPDto,
    request: Request,
  ) {
    const { email, userType } = forgotPasswordSendOTP;
    if (userType === 'ADMIN') {
      const admin = await this.adminRepository.findOne({
        where: { email },
      });

      if (!admin) {
        this.logger.warn(`Admin with email '${email}' not found`);
        throw new NotFoundException(`Admin with email '${email}' not found`);
      }

      const { device, browser, os } = parseUserAgent(request);
      const adminActivityLog = this.userActivityLogRepository.create({
        adminId: admin.id,
        action: ActivityAction.FORGOT_PASSWORD_SEND_OTP,
        description: 'Forgot password request sent',
        ipAddress: request?.ip,
        userAgent: request?.headers['user-agent'],
        device,
        browser,
        os,
        location: request?.headers['cf-ipcountry'] as string,
      });
      await this.userActivityLogRepository.save(adminActivityLog);

      const code = this.generateVerificationCode();
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

      const cacheKey = this.cacheKeyRepository.create({
        userId: null,
        adminId: admin.id,
        service: CacheKeyService.RESET_PASSWORD,
        code,
        expiresAt,
        status: CacheKeyStatus.PENDING,
        attempts: 0,
        maxAttempts: 3,
      });
      await this.cacheKeyRepository.save(cacheKey);

      await this.emailServiceUtils.sendForgotPasswordResetCode({
        code,
        email: admin.email,
        userName: admin.fullName,
        fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
        expiresIn: 10,
      });

      this.logger.log(
        `Account with ID '${admin.id}' send forgot password request successfully`,
      );
      return {
        userId: admin.id,
      };
    }

    const user = await this.userRepository.findOne({
      where: { email },
    });

    if (!user) {
      this.logger.warn(`User with email '${email}' not found`);
      throw new NotFoundException(`User with email '${email}' not found`);
    }

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.FORGOT_PASSWORD_SEND_OTP,
      description: 'Forgot password request sent',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    await this.userActivityLogRepository.save(userActivityLog);

    const code = this.generateVerificationCode();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

    const cacheKey = this.cacheKeyRepository.create({
      userId: user.id,
      adminId: null,
      service: CacheKeyService.RESET_PASSWORD,
      code,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });
    await this.cacheKeyRepository.save(cacheKey);

    await this.emailServiceUtils.sendForgotPasswordResetCode({
      code,
      email: user.email,
      userName: user.fullName,
      fromUsername: this.configService.get<string>('EMAIL_FROM_NAME', ''),
      expiresIn: 10,
    });

    this.logger.log(
      `Account with ID '${user.id}' send forgot password request successfully`,
    );
    return {
      userId: user.id,
    };
  }

  async verifyPasswordResetOTPCode(
    verifyPasswordResetOTPCode: VerifyPasswordResetOTPCodeDto,
  ) {
    let otpVerification = await this.cacheKeyRepository.findOne({
      where: {
        userId: verifyPasswordResetOTPCode.userId,
        service: CacheKeyService.RESET_PASSWORD,
        status: CacheKeyStatus.PENDING,
      },
    });

    if (!otpVerification) {
      otpVerification = await this.cacheKeyRepository.findOne({
        where: {
          adminId: verifyPasswordResetOTPCode.userId,
          service: CacheKeyService.RESET_PASSWORD,
          status: CacheKeyStatus.PENDING,
        },
      });
    }

    if (!otpVerification) {
      this.logger.warn(
        `No pending otp verification found for account ID '${verifyPasswordResetOTPCode.userId}'`,
      );
      throw new BadRequestException('No pending otp verification found');
    }

    // Check if code has expired
    if (new Date() > otpVerification.expiresAt) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Verification code for account ID '${verifyPasswordResetOTPCode.userId}' has expired`,
      );
      throw new BadRequestException('Verification code has expired');
    }

    // Check if max attempts reached
    if (otpVerification.attempts >= otpVerification.maxAttempts) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Maximum verification attempts exceeded for account ID '${verifyPasswordResetOTPCode.userId}'`,
      );
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    otpVerification.attempts += 1;

    // Verify code
    if (otpVerification.code !== verifyPasswordResetOTPCode.code) {
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Invalid verification code for account ID '${verifyPasswordResetOTPCode.userId}'`,
      );
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as active
    otpVerification.status = CacheKeyStatus.VERIFIED;
    await this.cacheKeyRepository.save(otpVerification);

    const payload = {
      sub: verifyPasswordResetOTPCode.userId,
      userId: verifyPasswordResetOTPCode.userId,
      type: CacheKeyService.RESET_PASSWORD,
    };

    const accessToken = this.jwtService.sign(payload);

    this.logger.log(
      `Account with ID '${verifyPasswordResetOTPCode.userId}' verified reset password request successfully`,
    );
    return {
      userId: verifyPasswordResetOTPCode.userId,
      accessToken,
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto, request: Request) {
    // Validate and decode access token
    try {
      await this.jwtService.verifyAsync(resetPasswordDto.accessToken);
    } catch {
      throw new UnauthorizedException('Access token verification failed');
    }

    const decoded = this.jwtService.decode(resetPasswordDto.accessToken);

    const { userId, type } = decoded as {
      userId?: string;
      type?: CacheKeyService;
    };

    if (!userId) {
      this.logger.warn('Invalid reset password token payload');
      throw new BadRequestException('Invalid reset password token');
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      const admin = await this.adminRepository.findOne({
        where: { id: userId },
      });

      if (!admin) {
        this.logger.warn(
          `Account with ID '${userId}' not found after token verification`,
        );
        throw new NotFoundException(
          `Account with ID '${userId}' not found after token verification`,
        );
      }

      if (type !== CacheKeyService.RESET_PASSWORD) {
        this.logger.warn(
          `Invalid access token type for account ID '${userId}'`,
        );
        throw new BadRequestException(
          `Invalid access token type for account ID '${userId}'`,
        );
      }

      admin.password = resetPasswordDto.newPassword;
      await this.adminRepository.save(admin);

      const { device, browser, os } = parseUserAgent(request);
      const adminActivityLog = this.userActivityLogRepository.create({
        adminId: admin.id,
        action: ActivityAction.CHANGE_PASSWORD,
        description: 'Admin password changed successfully',
        ipAddress: request?.ip,
        userAgent: request?.headers['user-agent'],
        device,
        browser,
        os,
        location: request?.headers['cf-ipcountry'] as string,
      });
      this.logger.log(
        `Admin with ID '${admin.id}' changed password successfully`,
      );
      await this.userActivityLogRepository.save(adminActivityLog);

      return;
    }

    if (type !== CacheKeyService.RESET_PASSWORD) {
      this.logger.warn(`Invalid access token type for account ID '${userId}'`);
      throw new NotFoundException(
        `Invalid access token type for account ID '${userId}'`,
      );
    }

    user.password = resetPasswordDto.newPassword;
    await this.userRepository.save(user);

    const { device, browser, os } = parseUserAgent(request);
    const userActivityLog = this.userActivityLogRepository.create({
      userId: user.id,
      action: ActivityAction.CHANGE_PASSWORD,
      description: 'User password changed successfully',
      ipAddress: request?.ip,
      userAgent: request?.headers['user-agent'],
      device,
      browser,
      os,
      location: request?.headers['cf-ipcountry'] as string,
    });
    this.logger.log(`User with ID '${user.id}' changed password successfully`);
    await this.userActivityLogRepository.save(userActivityLog);
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
