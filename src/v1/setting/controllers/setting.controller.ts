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
import { SMTPResponseDto } from '../dto/smtp-response.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ApiResponse } from 'src/common/interfaces/api-response.interface';
import { CreateSMTPDto } from '../dto/create-smtp-setting.dto';

@Controller({ path: 'settings', version: '1' })
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
  async createSMTPSettings(@Body() createSMTPDto: CreateSMTPDto) {
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
}
