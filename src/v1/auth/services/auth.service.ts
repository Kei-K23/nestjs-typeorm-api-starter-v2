import {
  Injectable,
  UnauthorizedException,
  BadRequestException,
  NotFoundException,
  Logger,
  InternalServerErrorException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { ConfigService } from '@nestjs/config';
import {
  LoginProvider,
  User,
  UserRegistrationStage,
} from 'src/v1/user/entities/user.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import { RefreshToken } from '../entities/refresh-token.entity';
import { AuthenticatedUser, JwtPayload } from '../interfaces/user.interface';
import { ActivityLogService } from 'src/v1/activity-log/services/activity-log.service';
import { AuditLogService } from 'src/v1/activity-log/services/audit-log.service';
import { LogAction } from 'src/v1/activity-log/constants/log-action.enum';
import { CreateActivityLogData } from 'src/v1/activity-log/interfaces/create-activity-log.interface';
import { CreateAuditLogData } from 'src/v1/activity-log/interfaces/create-audit-log.interface';
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
import { UserRegisterOTPRequestDto } from '../dto/user-register-otp-request.dto';
import { SMSPhoServiceUtils } from 'src/common/utils/sms-pho-service.utils';
import { FileUploadService } from 'src/common/services/file-upload.service';
import { UserRegisterOTPVerifyDto } from '../dto/user-register-otp-verify.dto';
import { UserRegisterPasswordSetupDto } from '../dto/user-register-password-setup.dto';
import { UserRegisterAccountSetupDto } from '../dto/user-register-account-setup.dto';
import { UserGoogleLoginDto } from '../dto/user-google-login.dto';
import { UserAppleLoginDto } from '../dto/user-apple-login.dto';
import { UserForgotPasswordSendOTPDto } from '../dto/user-forgot-password-send-otp.dto';

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
    @InjectRepository(CacheKey)
    private cacheKeyRepository: Repository<CacheKey>,
    private jwtService: JwtService,
    private configService: ConfigService,
    private twoFactorService: TwoFactorService,
    private activityLogService: ActivityLogService,
    private auditLogService: AuditLogService,
    private s3ClientUtils: S3ClientUtils,
    private emailServiceUtils: EmailServiceUtils,
    private smsPhoServiceUtils: SMSPhoServiceUtils,
    private fileUploadService: FileUploadService,
  ) {}

  private getClientIp(request: Request): string {
    const forwarded = request.headers['x-forwarded-for'] as string;
    return (
      forwarded?.split(',')[0]?.trim() ||
      (request.headers['x-real-ip'] as string) ||
      request.socket?.remoteAddress ||
      request.ip ||
      'unknown'
    );
  }

  private buildRequestContext(
    request: Request,
  ): Pick<
    CreateActivityLogData,
    'ipAddress' | 'userAgent' | 'device' | 'browser' | 'os' | 'location'
  > {
    const { device, browser, os } = parseUserAgent(request);
    return {
      ipAddress: this.getClientIp(request),
      userAgent: (request.headers['user-agent'] as string) || '',
      device,
      browser,
      os,
      location: (request.headers['cf-ipcountry'] as string) || undefined,
    };
  }

  private async logUserActivity(
    request: Request,
    userId: string,
    action: LogAction,
    description: string,
    extra?: Partial<CreateActivityLogData>,
  ): Promise<void> {
    await this.activityLogService
      .create({
        userId,
        action,
        description,
        ...this.buildRequestContext(request),
        ...extra,
      })
      .catch((err) => this.logger.error('Failed to write activity log:', err));
  }

  private async logAdminAudit(
    request: Request,
    adminId: string,
    action: LogAction,
    description: string,
    extra?: Partial<CreateAuditLogData>,
  ): Promise<void> {
    await this.auditLogService
      .create({
        adminId,
        action,
        description,
        entityName: extra?.entityName ?? 'admin',
        entityId: extra?.entityId ?? adminId,
        ...this.buildRequestContext(request),
        ...extra,
      })
      .catch((err) => this.logger.error('Failed to write audit log:', err));
  }

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
    const { password: _, ...result } = admin;
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

  private async completeUserLogin(user: User, request: Request) {
    const payload: JwtPayload = {
      sub: user.id,
      subjectType: 'USER',
      userId: user.id,
    };

    const accessToken = this.jwtService.sign(payload);

    await this.revokeAllUserTokens(user.id, false);
    const refreshToken = await this.generateRefreshToken(user.id, 'user');

    this.logger.log(`User with ID '${user.id}' logged in successfully`);
    await this.logUserActivity(
      request,
      user.id,
      LogAction.LOGIN,
      'User logged in successfully',
    );

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        900000,
      ),
      refreshTokenExpiresAt: this.configService.get<number>(
        'JWT_REFRESH_EXPIRATION',
        2592000000,
      ),
      user: {
        id: user.id,
        fcmToken: user.fcmToken,
      },
    };
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

    user.fcmToken = loginDto.fcmToken;
    user.lastLoginAt = new Date();
    await this.userRepository.save(user);

    return this.completeUserLogin(user, request);
  }

  async userAppleLogin(userAppleLoginDto: UserAppleLoginDto, request: Request) {
    const { token, fcmToken } = userAppleLoginDto;

    const decodedToken = this.jwtService.decode(token);

    if (!decodedToken) {
      throw new UnauthorizedException('Invalid Apple token');
    }

    const { sub, email } = decodedToken;
    const whereConditions: any[] = [{ appleId: sub }];
    if (email) {
      whereConditions.push({ email });
    }
    let user = await this.userRepository.findOne({
      where: whereConditions,
    });

    if (!user) {
      // Create new user
      user = this.userRepository.create({
        appleId: sub,
        email,
        registrationStage: UserRegistrationStage.PASSWORD_SETUP,
        fcmToken,
        loginProvider: LoginProvider.APPLE,
        lastLoginAt: new Date(),
      });

      await this.userRepository.save(user);

      return {
        userId: user.id,
        email: user.email,
        fullName: user.fullName,
        currentUserRegistrationStage: user.registrationStage,
        nextUserRegistrationStage: UserRegistrationStage.ACCOUNT_SETUP,
        message:
          'Apple OAuth successful and account setup required to complete the register process',
      };
    } else {
      if (user.isBanned) {
        this.logger.warn(`Banned user with ID '${user.id}' attempted to login`);
        throw new UnauthorizedException('Your account has been banned');
      }

      // Update existing user with appleId if not present
      if (!user.appleId) {
        user.appleId = sub;
      }

      if (fcmToken) {
        user.fcmToken = fcmToken;
      }

      if (user.registrationStage === UserRegistrationStage.PASSWORD_SETUP) {
        // If your account is still in PASSWORD_SETUP but user record is exist
        await this.userRepository.save(user);
        return {
          userId: user.id,
          email: user.email,
          fullName: user.fullName,
          currentUserRegistrationStage: user.registrationStage,
          nextUserRegistrationStage: UserRegistrationStage.ACCOUNT_SETUP,
          message:
            'Apple OAuth successful and account setup required to complete the register process',
        };
      }
    }

    user.lastLoginAt = new Date();
    if (fcmToken) {
      user.fcmToken = fcmToken;
    }

    await this.userRepository.save(user);

    await this.logUserActivity(
      request,
      user.id,
      LogAction.LOGIN,
      'User logged in via Apple successfully',
    );
    return this.completeUserLogin(user, request);
  }

  async userRegisterOTPRequest(
    userRegisterOTPRequest: UserRegisterOTPRequestDto,
  ) {
    const user = await this.userRepository.findOne({
      where: {
        phone: userRegisterOTPRequest.phone,
        registrationStage: UserRegistrationStage.ACCOUNT_SETUP,
      },
    });

    if (user) {
      this.logger.warn(
        `User with phone '${userRegisterOTPRequest.phone}' already exists`,
      );
      throw new UnauthorizedException('User already exists');
    }

    const { success, requestId } = await this.smsPhoServiceUtils.sendOTP({
      to: userRegisterOTPRequest.phone,
      message:
        "[{brand}] Dear customer, your OTP code is {code} for register. It'll expire in 30 minutes.",
      ttl: 1800,
      pinLength: 6,
    });

    if (!success) {
      throw new InternalServerErrorException('Failed to send OTP Verification');
    }

    return {
      requestId,
      message: 'OTP verification code sent to your phone',
    };
  }

  async userRegisterOTPVerify(userRegisterOTPVerify: UserRegisterOTPVerifyDto) {
    const user = await this.userRepository.findOne({
      where: {
        phone: userRegisterOTPVerify.phone,
      },
    });

    if (user) {
      if (user.registrationStage === UserRegistrationStage.OTP_VERIFY) {
        return {
          userId: user.id,
          currentUserRegistrationStage: user.registrationStage,
          nextUserRegistrationStage: UserRegistrationStage.PASSWORD_SETUP,
          message: 'User is already OTP_VERIFY',
        };
      }

      if (user.registrationStage === UserRegistrationStage.PASSWORD_SETUP) {
        return {
          userId: user.id,
          currentUserRegistrationStage: user.registrationStage,
          nextUserRegistrationStage: UserRegistrationStage.ACCOUNT_SETUP,
          message: 'User is already PASSWORD_SETUP',
        };
      }

      if (user.registrationStage === UserRegistrationStage.ACCOUNT_SETUP) {
        // return {
        //   userId: user.id,
        //   currentUserRegistrationStage: user.registrationStage,
        //   message:
        //     'User is already ACCOUNT_SETUP and cannot be registered again',
        // };
        this.logger.warn(
          `User with phone '${userRegisterOTPVerify.phone}' already exists`,
        );
        throw new UnauthorizedException(
          'User is already ACCOUNT_SETUP and cannot be registered again',
        );
      }
    }

    const { success } = await this.smsPhoServiceUtils.verifyOTP({
      requestId: userRegisterOTPVerify.requestId,
      code: userRegisterOTPVerify.otp,
    });

    if (success) {
      const newUser = this.userRepository.create({
        fcmToken: userRegisterOTPVerify.fcmToken,
        registrationStage: UserRegistrationStage.OTP_VERIFY,
        phone: userRegisterOTPVerify.phone,
      });
      await this.userRepository.save(newUser);
      return {
        userId: newUser.id,
        currentUserRegistrationStage: newUser.registrationStage,
        nextUserRegistrationStage: UserRegistrationStage.PASSWORD_SETUP,
        message: 'OTP verification succeeded',
      };
    }

    throw new BadRequestException('Invalid OTP');
  }

  async userRegisterPasswordSetup(
    userRegisterPasswordSetupDto: UserRegisterPasswordSetupDto,
  ) {
    const user = await this.userRepository.findOne({
      where: {
        id: userRegisterPasswordSetupDto.userId,
        registrationStage: UserRegistrationStage.OTP_VERIFY,
      },
    });

    if (!user) {
      this.logger.warn(
        `User with ID '${userRegisterPasswordSetupDto.userId}' not found`,
      );
      throw new UnauthorizedException('User not found');
    }

    if (user.registrationStage !== UserRegistrationStage.OTP_VERIFY) {
      this.logger.warn(
        `User with ID '${userRegisterPasswordSetupDto.userId}' is not in OTP_VERIFY stage`,
      );
      throw new UnauthorizedException('User not in OTP_VERIFY stage');
    }

    if (
      userRegisterPasswordSetupDto.password !==
      userRegisterPasswordSetupDto.confirmPassword
    ) {
      this.logger.warn(
        `Passwords do not match for user with ID '${userRegisterPasswordSetupDto.userId}'`,
      );
      throw new BadRequestException('Passwords do not match');
    }

    user.password = userRegisterPasswordSetupDto.password;
    user.registrationStage = UserRegistrationStage.PASSWORD_SETUP;
    await this.userRepository.save(user);

    return {
      userId: user.id,
      currentUserRegistrationStage: user.registrationStage,
      nextUserRegistrationStage: UserRegistrationStage.ACCOUNT_SETUP,
      message: 'Password setup succeeded',
    };
  }

  async userRegisterAccountSetup(
    userRegisterAccountSetupDto: UserRegisterAccountSetupDto,
    file?: Express.Multer.File,
    request?: Request,
  ) {
    const user = await this.userRepository.findOne({
      where: {
        id: userRegisterAccountSetupDto.userId,
        registrationStage: UserRegistrationStage.PASSWORD_SETUP,
      },
    });

    if (!user) {
      this.logger.warn(
        `User with ID '${userRegisterAccountSetupDto.userId}' not found`,
      );
      throw new UnauthorizedException('User not found');
    }

    if (user.registrationStage !== UserRegistrationStage.PASSWORD_SETUP) {
      this.logger.warn(
        `User with ID '${userRegisterAccountSetupDto.userId}' is not in PASSWORD_SETUP stage`,
      );
      throw new UnauthorizedException('User not in PASSWORD_SETUP stage');
    }

    const existingProfileImageUrl = user.profileImageUrl || '';

    let newProfileImageUrl =
      userRegisterAccountSetupDto.profileImageUrl ?? existingProfileImageUrl;

    if (file) {
      const uploadedKey = await this.fileUploadService.uploadProfileImage(
        file,
        'users/profile',
      );
      if (uploadedKey) {
        newProfileImageUrl = uploadedKey;
      }
    }

    user.email = userRegisterAccountSetupDto.email ?? user.email;
    user.fullName = userRegisterAccountSetupDto.fullName;
    user.dateOfBirth = userRegisterAccountSetupDto.dateOfBirth;
    user.gender = userRegisterAccountSetupDto.gender ?? user.gender;
    user.preferLanguage =
      userRegisterAccountSetupDto.preferLanguage ?? user.preferLanguage;
    user.profileImageUrl = newProfileImageUrl;
    user.registrationStage = UserRegistrationStage.ACCOUNT_SETUP;
    user.fcmToken = userRegisterAccountSetupDto.fcmToken ?? user.fcmToken;

    await this.userRepository.save(user);

    const imageChanged = newProfileImageUrl !== (existingProfileImageUrl || '');

    if (imageChanged && existingProfileImageUrl) {
      await this.s3ClientUtils.deleteObject(existingProfileImageUrl);
    }

    await this.logUserActivity(
      request as Request,
      user.id,
      LogAction.REGISTER,
      'User registration completed',
    );
    const loginData = await this.completeUserLogin(user, request as Request);

    return {
      userId: user.id,
      currentUserRegistrationStage: user.registrationStage,
      loginData,
      message: 'Account setup succeeded',
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

    const refreshToken = await this.generateRefreshToken(admin.id, 'admin');

    const previousLastLoginAt = admin.lastLoginAt;
    const lastLoginAt = new Date();

    await this.adminRepository.update(admin.id, { lastLoginAt });
    await this.logAdminAudit(
      request,
      admin.id,
      LogAction.LOGIN,
      'Admin logged in successfully',
      {
        oldValue: { lastLoginAt: previousLastLoginAt },
        newValue: { lastLoginAt },
      },
    );

    return {
      accessToken,
      refreshToken,
      accessTokenExpiresAt: this.configService.get<number>(
        'JWT_EXPIRATION',
        900000,
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
    const tokenHash = crypto
      .createHash('sha256')
      .update(refreshTokenString)
      .digest('hex');

    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: tokenHash, isRevoked: false },
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
      this.logger.warn('Invalid refresh token provided');
      throw new UnauthorizedException('Invalid or expired refresh token');
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
        900000,
      ),
      user: {
        id: ownerId,
      },
    };
  }

  async logout(refreshTokenString: string, user: AuthenticatedUser) {
    const tokenHash = crypto
      .createHash('sha256')
      .update(refreshTokenString)
      .digest('hex');

    const refreshToken = await this.refreshTokenRepository.findOne({
      where: { token: tokenHash },
    });

    if (refreshToken) {
      refreshToken.isRevoked = true;
      await this.refreshTokenRepository.save(refreshToken);
    }

    if (user) {
      await this.revokeAllUserTokens(user.id);
      this.logger.log(`User with ID '${user.id}' logged out successfully`);
    }
  }

  async revokeAllUserTokens(userId: string, clearFcmToken: boolean = true) {
    await this.refreshTokenRepository.update(
      { userId, isRevoked: false },
      { isRevoked: true },
    );

    const updateData: any = {
      lastLogoutAt: new Date().toISOString(),
    };

    if (clearFcmToken) {
      updateData.fcmToken = '';
    }

    await this.userRepository.update(userId, updateData);
  }

  async revokeAllAdminTokens(adminId: string) {
    await this.refreshTokenRepository.update(
      { adminId, isRevoked: false },
      { isRevoked: true },
    );
  }

  /**
   * Generates a refresh token, stores a SHA-256 hash in the database,
   * and returns the plaintext token to the caller.
   * Storing a hash ensures that a database leak does not expose active sessions.
   */
  private async generateRefreshToken(
    ownerId: string,
    ownerType: 'user' | 'admin',
  ): Promise<string> {
    const token = this.jwtService.sign(
      { sub: ownerId },
      {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<number>(
          'JWT_REFRESH_EXPIRATION',
          2592000000,
        ),
      },
    );

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30);

    const refreshToken = this.refreshTokenRepository.create({
      token: tokenHash,
      ...(ownerType === 'user' ? { userId: ownerId } : { adminId: ownerId }),
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
    file?: Express.Multer.File,
  ) {
    if (subjectType === 'ADMIN') {
      const admin = await this.adminRepository.findOne({
        where: { id: userId },
      });

      if (!admin) {
        this.logger.warn(`Admin with ID '${userId}' not found`);
        throw new NotFoundException(`Admin with ID '${userId}' not found`);
      }

      const hasBodyProfileImageUrl =
        typeof updateProfileDto.profileImageUrl === 'string' &&
        updateProfileDto.profileImageUrl.length >= 0;

      let newProfileImageUrl = admin.profileImageUrl || '';

      if (file) {
        const uploadedKey = await this.fileUploadService.uploadProfileImage(
          file,
          'admins/profile',
        );
        if (uploadedKey) {
          newProfileImageUrl = uploadedKey;
        }
      } else if (hasBodyProfileImageUrl) {
        newProfileImageUrl = updateProfileDto.profileImageUrl || '';
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
        profileImageUrl: newProfileImageUrl,
      });

      if (updateProfileDto.password) {
        updatedAdmin.password = updateProfileDto.password;
      }

      const savedAdmin = await this.adminRepository.save(updatedAdmin);

      const imageChanged = newProfileImageUrl !== (admin.profileImageUrl || '');

      if (
        imageChanged &&
        admin.profileImageUrl &&
        (await this.s3ClientUtils.objectExists(admin.profileImageUrl))
      ) {
        await this.s3ClientUtils.deleteObject(admin.profileImageUrl);
      }

      await this.logAdminAudit(
        request,
        admin.id,
        LogAction.UPDATE_PROFILE,
        'Admin profile updated successfully',
      );

      const { password: _, ...result } = savedAdmin;

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

    const hasBodyProfileImageUrl =
      typeof updateProfileDto.profileImageUrl === 'string' &&
      updateProfileDto.profileImageUrl.length >= 0;

    let newProfileImageUrl = user.profileImageUrl || '';

    if (file) {
      const uploadedKey = await this.fileUploadService.uploadProfileImage(
        file,
        'users/profile',
      );
      if (uploadedKey) {
        newProfileImageUrl = uploadedKey;
      }
    } else if (hasBodyProfileImageUrl) {
      newProfileImageUrl = updateProfileDto.profileImageUrl || '';
    }

    const updatedUser = await this.userRepository.preload({
      id: userId,
      ...updateProfileDto,
      profileImageUrl: newProfileImageUrl,
    });
    if (!updatedUser) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new BadRequestException(`User with ID '${userId}' not found`);
    }

    if (updateProfileDto.password) {
      updatedUser.password = updateProfileDto.password;
    }

    const savedUser = await this.userRepository.save(updatedUser);

    const imageChanged = newProfileImageUrl !== (user.profileImageUrl || '');

    if (
      imageChanged &&
      user.profileImageUrl &&
      (await this.s3ClientUtils.objectExists(user.profileImageUrl))
    ) {
      await this.s3ClientUtils.deleteObject(user.profileImageUrl);
    }

    await this.logUserActivity(
      request,
      user.id,
      LogAction.UPDATE_PROFILE,
      'User profile updated successfully',
    );

    const { password: _, ...result } = savedUser;

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

      this.logger.log(
        `Admin with ID '${admin.id}' password changed successfully`,
      );
      await this.logAdminAudit(
        request,
        admin.id,
        LogAction.CHANGE_PASSWORD,
        'Admin password changed successfully',
      );

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

    this.logger.log(`User with ID '${user.id}' password changed successfully`);
    await this.logUserActivity(
      request,
      user.id,
      LogAction.CHANGE_PASSWORD,
      'User password changed successfully',
    );
  }

  async deleteProfile(userId: string, request: Request): Promise<void> {
    const user = await this.userRepository.findOne({
      where: { id: userId },
      relations: ['refreshTokens'],
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    // Log before deletion so userId FK still exists
    await this.logUserActivity(
      request,
      user.id,
      LogAction.DELETE_ACCOUNT,
      'User account deleted successfully',
    );

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

      await this.logAdminAudit(
        request,
        admin.id,
        LogAction.FORGOT_PASSWORD_OTP,
        'Forgot password OTP sent',
      );

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

    await this.logUserActivity(
      request,
      user.id,
      LogAction.FORGOT_PASSWORD_OTP,
      'Forgot password OTP sent',
    );

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
    if (Date.now() > otpVerification.expiresAt.getTime()) {
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

      this.logger.log(
        `Admin with ID '${admin.id}' changed password successfully`,
      );
      await this.logAdminAudit(
        request,
        admin.id,
        LogAction.RESET_PASSWORD,
        'Admin password reset successfully',
      );

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

    this.logger.log(`User with ID '${user.id}' changed password successfully`);
    await this.logUserActivity(
      request,
      user.id,
      LogAction.RESET_PASSWORD,
      'User password reset successfully',
    );
  }

  async userPasswordResetOTPSend(
    userForgotPasswordSendOTP: UserForgotPasswordSendOTPDto,
    request: Request,
  ) {
    const { phone } = userForgotPasswordSendOTP;

    const user = await this.userRepository.findOne({
      where: { phone },
    });

    if (!user) {
      this.logger.warn(`User with phone '${phone}' not found`);
      throw new NotFoundException(`User with phone '${phone}' not found`);
    }

    await this.logUserActivity(
      request,
      user.id,
      LogAction.FORGOT_PASSWORD_OTP,
      'Forgot password OTP sent',
    );

    const expiresAt = new Date(Date.now() + 10 * 60 * 1000);
    const message =
      "[{brand}] Dear customer, your OTP code is {code} for password reset. It'll expire in 30 minutes.";

    const smsResponse = await this.smsPhoServiceUtils.sendOTP({
      to: user.phone,
      message,
    });

    const cacheKey = this.cacheKeyRepository.create({
      userId: user.id,
      adminId: null,
      service: CacheKeyService.RESET_PASSWORD,
      code: 'SMS_OTP', // Placeholder as code is handled by SMS provider
      requestId: smsResponse.requestId,
      expiresAt,
      status: CacheKeyStatus.PENDING,
      attempts: 0,
      maxAttempts: 3,
    });
    await this.cacheKeyRepository.save(cacheKey);

    this.logger.log(
      `Account with ID '${user.id}' send forgot password request successfully`,
    );
    return {
      userId: user.id,
    };
  }

  async userVerifyPasswordResetOTPCode(
    verifyPasswordResetOTPCodeDto: VerifyPasswordResetOTPCodeDto,
  ) {
    const { userId, code } = verifyPasswordResetOTPCodeDto;

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      this.logger.warn(`User with ID '${userId}' not found`);
      throw new NotFoundException(`User with ID '${userId}' not found`);
    }

    const otpVerification = await this.cacheKeyRepository.findOne({
      where: {
        userId,
        service: CacheKeyService.RESET_PASSWORD,
        status: CacheKeyStatus.PENDING,
      },
      order: { createdAt: 'DESC' },
    });

    if (!otpVerification) {
      this.logger.warn(`Invalid verification code for account ID '${userId}'`);
      throw new BadRequestException('Invalid verification code');
    }

    if (otpVerification.expiresAt < new Date()) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(`Verification code expired for account ID '${userId}'`);
      throw new BadRequestException('Verification code expired');
    }

    if (otpVerification.attempts >= otpVerification.maxAttempts) {
      otpVerification.status = CacheKeyStatus.EXPIRED;
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Maximum verification attempts exceeded for account ID '${userId}'`,
      );
      throw new BadRequestException('Maximum verification attempts exceeded');
    }

    // Increment attempts
    otpVerification.attempts += 1;

    // Verify code via SMSPoh
    if (otpVerification.requestId) {
      try {
        await this.smsPhoServiceUtils.verifyOTP({
          requestId: otpVerification.requestId,
          code,
        });
      } catch {
        await this.cacheKeyRepository.save(otpVerification);
        this.logger.warn(
          `Invalid verification code for account ID '${userId}'`,
        );
        throw new BadRequestException('Invalid verification code');
      }
    } else {
      await this.cacheKeyRepository.save(otpVerification);
      this.logger.warn(
        `Invalid verification flow (missing requestId) for account ID '${userId}'`,
      );
      throw new BadRequestException('Invalid verification code');
    }

    // Mark as verified
    otpVerification.status = CacheKeyStatus.VERIFIED;
    otpVerification.code = code;
    await this.cacheKeyRepository.save(otpVerification);

    const payload = {
      sub: userId,
      userId,
      type: CacheKeyService.RESET_PASSWORD,
    };

    const accessToken = this.jwtService.sign(payload);

    this.logger.log(
      `Account with ID '${userId}' verified reset password request successfully`,
    );
    return {
      userId,
      accessToken,
    };
  }

  async userResetPassword(
    resetPasswordDto: ResetPasswordDto,
    request: Request,
  ) {
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

    if (!userId || type !== CacheKeyService.RESET_PASSWORD) {
      this.logger.warn('Invalid reset password token payload');
      throw new BadRequestException('Invalid reset password token');
    }

    const user = await this.userRepository.findOne({
      where: { id: userId },
    });

    if (!user) {
      this.logger.warn(
        `Account with ID '${userId}' not found after token verification`,
      );
      throw new NotFoundException(
        `Account with ID '${userId}' not found after token verification`,
      );
    }

    user.password = resetPasswordDto.newPassword;
    await this.userRepository.save(user);

    await this.revokeAllUserTokens(userId);

    this.logger.log(`User with ID '${user.id}' changed password successfully`);
    await this.logUserActivity(
      request,
      user.id,
      LogAction.RESET_PASSWORD,
      'User password reset successfully',
    );
  }

  async userGoogleLogin(
    userGoogleLoginDto: UserGoogleLoginDto,
    request: Request,
  ) {
    const { token, fcmToken } = userGoogleLoginDto;
    const decodedToken = this.jwtService.decode(token);

    if (!decodedToken) {
      throw new UnauthorizedException('Invalid Google token');
    }

    const { sub, email, name } = decodedToken;
    const whereConditions: any[] = [{ googleId: sub }];
    if (email) {
      whereConditions.push({ email });
    }
    let user = await this.userRepository.findOne({
      where: whereConditions,
    });

    if (!user) {
      // Create new user
      user = this.userRepository.create({
        googleId: sub,
        email,
        fullName: name,
        registrationStage: UserRegistrationStage.PASSWORD_SETUP,
        fcmToken,
        loginProvider: LoginProvider.GOOGLE,
        lastLoginAt: new Date(),
      });

      await this.userRepository.save(user);

      return {
        userId: user.id,
        email: user.email,
        fullName: user.fullName,
        currentUserRegistrationStage: user.registrationStage,
        nextUserRegistrationStage: UserRegistrationStage.ACCOUNT_SETUP,
        message:
          'Google OAuth successful and account setup required to complete the register process',
      };
    } else {
      if (user.isBanned) {
        this.logger.warn(`Banned user with ID '${user.id}' attempted to login`);
        throw new UnauthorizedException('Your account has been banned');
      }

      // Update existing user with googleId if not present
      if (!user.googleId) {
        user.googleId = sub;
      }

      if (fcmToken) {
        user.fcmToken = fcmToken;
      }

      if (user.registrationStage === UserRegistrationStage.PASSWORD_SETUP) {
        // If your account is still in ACCOUNT_SETUP but user record is exist
        await this.userRepository.save(user);
        return {
          userId: user.id,
          email: user.email,
          fullName: user.fullName,
          currentUserRegistrationStage: user.registrationStage,
          nextUserRegistrationStage: UserRegistrationStage.ACCOUNT_SETUP,
          message:
            'Google OAuth successful and account setup required to complete the register process',
        };
      }
    }

    user.lastLoginAt = new Date();
    if (fcmToken) {
      user.fcmToken = fcmToken;
    }
    await this.userRepository.save(user);

    await this.logUserActivity(
      request,
      user.id,
      LogAction.LOGIN,
      'User logged in via Google successfully',
    );
    return this.completeUserLogin(user, request);
  }

  private generateVerificationCode(): string {
    return crypto.randomInt(100000, 999999).toString();
  }
}
