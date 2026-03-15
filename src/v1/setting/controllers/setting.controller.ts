import {
  Controller,
  UseGuards,
  Post,
  Get,
  Body,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { SettingService } from '../services/setting.service';
import { CreateSMTPDto } from '../dto/create-smtp-setting.dto';
import { SMTPResponseDto } from '../dto/smtp-response.dto';
import { CreatePrivacyPolicyDto } from '../dto/create-privacy-policy.dto';
import { CreateTermAndConditionDto } from '../dto/create-term-and-condition.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ApiResponse } from 'src/common/interfaces/api-response.interface';

@Controller('api/v1/settings')
@UseGuards(JwtAuthGuard)
export class SettingController {
  constructor(private readonly settingService: SettingService) {}

  @Post('smtp')
  @UseGuards(PermissionsGuard)
  @RequirePermissions([
    {
      module: PermissionModule.SETTING,
      permission: 'create',
    },
    {
      module: PermissionModule.SETTING_SMTP,
      permission: 'create',
    },
  ])
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'SMTP settings setup successfully',
    resourceType: 'smtp-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  async createSMTPSettings(
    @Body() createSMTPDto: CreateSMTPDto,
  ): Promise<ApiResponse<SMTPResponseDto>> {
    const smtpSettings =
      await this.settingService.createSMTPSettings(createSMTPDto);
    return ResponseUtil.created(
      smtpSettings,
      'SMTP settings setup successfully',
    );
  }

  @Get('smtp')
  async getSMTPSettings(): Promise<ApiResponse<SMTPResponseDto>> {
    const smtpSettings = await this.settingService.getSMTPSettings();
    return ResponseUtil.success(
      smtpSettings,
      'SMTP settings retrieved successfully',
    );
  }

  @Post('privacy-policy')
  @UseGuards(PermissionsGuard)
  @RequirePermissions([
    {
      module: PermissionModule.SETTING,
      permission: 'create',
    },
    {
      module: PermissionModule.SETTING_PNV,
      permission: 'create',
    },
  ])
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'Privacy policy setup successfully',
    resourceType: 'privacy-policy-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  async createPrivacyPolicy(
    @Body() createPrivacyPolicyDto: CreatePrivacyPolicyDto,
  ): Promise<ApiResponse<any>> {
    const setting = await this.settingService.createPrivacyPolicy(
      createPrivacyPolicyDto,
    );
    return ResponseUtil.created(
      {
        privacyPolicy: setting.value,
        updatedAt: setting.updatedAt,
      },
      'Privacy policy setup successfully',
    );
  }

  @Get('privacy-policy')
  async getPrivacyPolicy(): Promise<ApiResponse<any>> {
    const setting = await this.settingService.getPrivacyPolicy();
    return ResponseUtil.success(
      {
        privacyPolicy: setting?.value || '',
        updatedAt: setting?.updatedAt || null,
      },
      'Privacy policy retrieved successfully',
    );
  }

  @Post('term-and-condition')
  @UseGuards(PermissionsGuard)
  @RequirePermissions([
    {
      module: PermissionModule.SETTING,
      permission: 'create',
    },
    {
      module: PermissionModule.SETTING_TNC,
      permission: 'create',
    },
  ])
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'Term and condition setup successfully',
    resourceType: 'term-and-condition-settings',
  })
  @HttpCode(HttpStatus.CREATED)
  async createTermAndCondition(
    @Body() createTermAndConditionDto: CreateTermAndConditionDto,
  ): Promise<ApiResponse<any>> {
    const setting = await this.settingService.createTermAndCondition(
      createTermAndConditionDto,
    );
    return ResponseUtil.created(
      {
        termAndCondition: setting.value,
        updatedAt: setting.updatedAt,
      },
      'Term and condition setup successfully',
    );
  }

  @Get('term-and-condition')
  async getTermAndCondition(): Promise<ApiResponse<any>> {
    const setting = await this.settingService.getTermAndCondition();
    return ResponseUtil.success(
      {
        termAndCondition: setting?.value || '',
        updatedAt: setting?.updatedAt || null,
      },
      'Term and condition retrieved successfully',
    );
  }
}
