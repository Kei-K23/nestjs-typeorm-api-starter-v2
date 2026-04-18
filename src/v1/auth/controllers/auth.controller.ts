import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Patch,
  Post,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from '../services/auth.service';
import { TwoFactorService } from '../services/two-factor.service';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { AuthenticatedUser } from '../interfaces/user.interface';
import { Request } from 'express';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { RefreshTokenDto } from '../dto/refresh-token.dto';
import { UpdateProfileDto } from '../dto/update-profile.dto';
import { ChangePasswordDto } from '../dto/change-password.dto';
import { VerifyTwoFactorDto } from '../dto/verify-two-factor.dto';
import { EnableTwoFactorDto } from '../dto/enable-two-factor.dto';
import { DisableTwoFactorDto } from '../dto/disable-two-factor.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { ForgotPasswordSendOTPDto } from '../dto/forgot-password-send-otp.dto';
import { UserForgotPasswordSendOTPDto } from '../dto/user-forgot-password-send-otp.dto';
import { VerifyPasswordResetOTPCodeDto } from '../dto/verify-password-reset-otp-code.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { UserLoginDto } from '../dto/user-login.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UserRegisterOTPRequestDto } from '../dto/user-register-otp-request.dto';
import { UserRegisterOTPVerifyDto } from '../dto/user-register-otp-verify.dto';
import { UserRegisterAccountSetupDto } from '../dto/user-register-account-setup.dto';
import { UserRegisterPasswordSetupDto } from '../dto/user-register-password-setup.dto';
import { UserGoogleLoginDto } from '../dto/user-google-login.dto';
import { UserAppleLoginDto } from '../dto/user-apple-login.dto';

@Controller({ path: 'auth', version: '1' })
export class AuthController {
  constructor(
    private authService: AuthService,
    private twoFactorService: TwoFactorService,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  @Post('admin-login')
  @HttpCode(200)
  async login(@Body() loginDto: AdminLoginDto, @Req() request: Request) {
    const result = await this.authService.adminLogin(loginDto, request);
    return ResponseUtil.success(result, 'Admin login successful');
  }

  @Post('user-login')
  @HttpCode(200)
  async userLogin(@Body() loginDto: UserLoginDto, @Req() request: Request) {
    const result = await this.authService.userLogin(loginDto, request);
    return ResponseUtil.success(result, 'User login successful');
  }

  @Post('user/google-login')
  @HttpCode(200)
  async userGoogleLogin(
    @Body() userGoogleLoginDto: UserGoogleLoginDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.userGoogleLogin(
      userGoogleLoginDto,
      request,
    );
    return ResponseUtil.success(result, 'User Google login successful');
  }

  @Post('user/apple-login')
  @HttpCode(200)
  async userAppleLogin(
    @Body() userAppleLoginDto: UserAppleLoginDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.userAppleLogin(
      userAppleLoginDto,
      request,
    );
    return ResponseUtil.success(result, 'User Apple login successful');
  }

  @Post('user-register-otp-request')
  @HttpCode(200)
  async userRegisterOTPRequest(
    @Body() userRegisterOTPRequestDto: UserRegisterOTPRequestDto,
  ) {
    const result = await this.authService.userRegisterOTPRequest(
      userRegisterOTPRequestDto,
    );
    return ResponseUtil.success(result, 'User register request successful');
  }

  @Post('user-register-otp-verify')
  @HttpCode(200)
  async userRegisterOTPVerify(
    @Body() userRegisterOTPVerifyDto: UserRegisterOTPVerifyDto,
  ) {
    const result = await this.authService.userRegisterOTPVerify(
      userRegisterOTPVerifyDto,
    );
    return ResponseUtil.success(result, 'User register OTP verify successful');
  }

  @Post('user-register-password-setup')
  @HttpCode(200)
  async userRegisterPasswordSetup(
    @Body() userRegisterPasswordSetupDto: UserRegisterPasswordSetupDto,
  ) {
    const result = await this.authService.userRegisterPasswordSetup(
      userRegisterPasswordSetupDto,
    );
    return ResponseUtil.success(
      result,
      'User register password setup successful',
    );
  }

  @Post('user-register-account-setup')
  @UseInterceptors(
    FileInterceptor('profileImage', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  @HttpCode(200)
  async userRegisterAccountSetup(
    @UploadedFile() file: Express.Multer.File,
    @Body() userRegisterAccountSetupDto: UserRegisterAccountSetupDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.userRegisterAccountSetup(
      userRegisterAccountSetupDto,
      file,
      request,
    );
    return ResponseUtil.success(
      result,
      'User register account setup successful',
    );
  }

  @Post('refresh')
  @HttpCode(200)
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    const result = await this.authService.refreshAccessToken(
      refreshTokenDto.refreshToken,
    );
    return ResponseUtil.success(result, 'Token refreshed successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  @LogActivity({
    action: ActivityAction.LOGOUT,
    description: 'User logged out successfully',
    resourceType: 'user',
    getResourceId: (result: AuthenticatedUser) => result.id?.toString(),
  })
  async logout(
    @Body() refreshTokenDto: RefreshTokenDto,
    @CurrentUser() user: AuthenticatedUser,
  ) {
    await this.authService.logout(refreshTokenDto.refreshToken, user);
    return ResponseUtil.success(null, 'Logout successful');
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  async getProfile(@CurrentUser() user: AuthenticatedUser) {
    if (
      user.profileImageUrl &&
      (await this.s3ClientUtils.objectExists(user.profileImageUrl))
    ) {
      user.profileImageUrl =
        (await this.s3ClientUtils.generatePresignedUrl(user.profileImageUrl)) ||
        '';
    }
    return ResponseUtil.success(user, 'Profile retrieved successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Patch('profile')
  @UseInterceptors(
    FileInterceptor('profileImage', {
      storage: memoryStorage(),
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  @HttpCode(200)
  async updateProfile(
    @CurrentUser() user: AuthenticatedUser,
    @UploadedFile() file: Express.Multer.File,
    @Body() updateProfileDto: UpdateProfileDto,
    @Req() request: Request,
  ) {
    const updatedUser = await this.authService.updateProfile(
      user.id,
      user.subjectType,
      updateProfileDto,
      request,
      file,
    );
    return ResponseUtil.success(updatedUser, 'Profile updated successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Patch('change-password')
  @HttpCode(200)
  async changePassword(
    @CurrentUser() user: AuthenticatedUser,
    @Body() changePasswordDto: ChangePasswordDto,
    @Req() request: Request,
  ) {
    await this.authService.changePassword(
      user.id,
      user.subjectType,
      changePasswordDto,
      request,
    );
    return ResponseUtil.success(
      null,
      'Password changed successfully. Please login again.',
    );
  }

  @UseGuards(JwtAuthGuard)
  @Delete('profile')
  @HttpCode(200)
  async deleteProfile(
    @CurrentUser() user: AuthenticatedUser,
    @Req() request: Request,
  ) {
    await this.authService.deleteProfile(user.id, request);
    return ResponseUtil.success(null, 'Profile deleted successfully');
  }

  @UseGuards(JwtAuthGuard)
  @Post('verify-2fa')
  @HttpCode(200)
  async verifyTwoFactor(
    @Body() verifyTwoFactorDto: VerifyTwoFactorDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.verifyTwoFactorAndLogin(
      verifyTwoFactorDto.userId,
      verifyTwoFactorDto.code,
      request,
    );
    return ResponseUtil.success(result, 'Two-factor authentication successful');
  }

  @Post('enable-2fa-verify')
  @HttpCode(200)
  async enableTwoFactorVerify(@Body() verifyTwoFactorDto: VerifyTwoFactorDto) {
    const result = await this.twoFactorService.verifyTwoFactor(
      verifyTwoFactorDto.userId,
      verifyTwoFactorDto.code,
    );
    return ResponseUtil.success(
      result,
      'Two-factor authentication enable successful',
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('enable-2fa')
  @HttpCode(200)
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Two-factor authentication enabled',
    resourceType: 'user',
    getResourceId: (result: AuthenticatedUser) => result.id?.toString(),
  })
  async enableTwoFactor(
    @CurrentUser() user: AuthenticatedUser,
    @Body() enableTwoFactorDto: EnableTwoFactorDto,
  ) {
    await this.twoFactorService.enableTwoFactor(
      user.id,
      enableTwoFactorDto.email,
    );
    return ResponseUtil.success(
      null,
      'Two-factor authentication enable verification code sent to email',
    );
  }

  @UseGuards(JwtAuthGuard)
  @Post('disable-2fa')
  @HttpCode(200)
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Two-factor authentication disabled',
    resourceType: 'user',
    getResourceId: (result: AuthenticatedUser) => result.id?.toString(),
  })
  async disableTwoFactor(
    @CurrentUser() user: AuthenticatedUser,
    @Body() disableTwoFactorDto: DisableTwoFactorDto,
  ) {
    await this.twoFactorService.disableTwoFactor(
      user.id,
      disableTwoFactorDto.password,
    );
    return ResponseUtil.success(null, 'Two-factor authentication disabled');
  }

  @Post('otp/send/forgot-password')
  @HttpCode(200)
  async forgotPasswordOTPSend(
    @Body() forgotPasswordSendOtpDto: ForgotPasswordSendOTPDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.passwordResetOTPSend(
      forgotPasswordSendOtpDto,
      request,
    );
    return ResponseUtil.success(
      result,
      'Forgot password reset OTP code sent to your email',
    );
  }

  @Post('otp/verify/forgot-password')
  @HttpCode(200)
  async passwordResetOTPVerify(
    @Body() verifyPasswordResetOTPCodeDto: VerifyPasswordResetOTPCodeDto,
  ) {
    const result = await this.authService.verifyPasswordResetOTPCode(
      verifyPasswordResetOTPCodeDto,
    );
    return ResponseUtil.success(
      result,
      'Successfully verify password reset code',
    );
  }

  @Post('reset-password')
  @HttpCode(200)
  async resetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() request: Request,
  ) {
    await this.authService.resetPassword(resetPasswordDto, request);
    return ResponseUtil.success(null, 'Successfully reset your password');
  }

  @Post('user/otp/send/forgot-password')
  @HttpCode(200)
  async userForgotPasswordOTPSend(
    @Body() userForgotPasswordSendOtpDto: UserForgotPasswordSendOTPDto,
    @Req() request: Request,
  ) {
    const result = await this.authService.userPasswordResetOTPSend(
      userForgotPasswordSendOtpDto,
      request,
    );
    return ResponseUtil.success(
      result,
      'Forgot password reset OTP code sent to your phone',
    );
  }

  @Post('user/otp/verify/forgot-password')
  @HttpCode(200)
  async userPasswordResetOTPVerify(
    @Body() verifyPasswordResetOTPCodeDto: VerifyPasswordResetOTPCodeDto,
  ) {
    const result = await this.authService.userVerifyPasswordResetOTPCode(
      verifyPasswordResetOTPCodeDto,
    );
    return ResponseUtil.success(
      result,
      'Successfully verify password reset code',
    );
  }

  @Post('user/reset-password')
  @HttpCode(200)
  async userResetPassword(
    @Body() resetPasswordDto: ResetPasswordDto,
    @Req() request: Request,
  ) {
    await this.authService.userResetPassword(resetPasswordDto, request);
    return ResponseUtil.success(null, 'Successfully reset your password');
  }
}
