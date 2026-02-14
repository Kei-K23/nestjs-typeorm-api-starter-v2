import {
  Controller,
  Post,
  Body,
  UseGuards,
  Get,
  Req,
  Delete,
  Patch,
  HttpCode,
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
import { VerifyPasswordResetOTPCodeDto } from '../dto/verify-password-reset-otp-code.dto';
import { ResetPasswordDto } from '../dto/reset-password.dto';
import { AdminLoginDto } from '../dto/admin-login.dto';
import { UserLoginDto } from '../dto/user-login.dto';

@Controller('api/v1/auth')
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
  async logout(@Body() refreshTokenDto: RefreshTokenDto) {
    await this.authService.logout(refreshTokenDto.refreshToken);
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
  @HttpCode(200)
  async updateProfile(
    @CurrentUser() user: AuthenticatedUser,
    @Body() updateProfileDto: UpdateProfileDto,
    @Req() request: Request,
  ) {
    const updatedUser = await this.authService.updateProfile(
      user.id,
      user.subjectType,
      updateProfileDto,
      request,
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
}
