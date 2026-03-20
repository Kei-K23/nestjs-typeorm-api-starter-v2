import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ActivityLogService } from '../services/activity-log.service';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { RolesGuard } from 'src/v1/auth/guards/roles.guard';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';

@Controller('/api/v1/')
@UseGuards(JwtAuthGuard, RolesGuard)
export class ActivityLogController {
  constructor(private readonly activityLogService: ActivityLogService) {}

  @Get('user-logs')
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'read',
    },
    {
      module: PermissionModule.ADMIN_USER_LOGS,
      permission: 'read',
    },
  ])
  async findAllUserLogs(@Query() filterDto: FilterActivityLogDto) {
    const result = await this.activityLogService.findAll({
      ...filterDto,
      isActivityLog: true,
    });

    if (filterDto.getAll) {
      return ResponseUtil.success(
        result.data,
        'All user logs retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      filterDto.page || 1,
      filterDto.limit || 10,
      'User logs retrieved successfully',
    );
  }

  @Get('audit-logs')
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'read',
    },
    {
      module: PermissionModule.ADMIN_AUDIT_LOGS,
      permission: 'read',
    },
  ])
  async findAllAuditLogs(@Query() filterDto: FilterActivityLogDto) {
    const result = await this.activityLogService.findAll({
      ...filterDto,
      isActivityLog: false,
    });

    if (filterDto.getAll) {
      return ResponseUtil.success(
        result.data,
        'All audit logs retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      filterDto.page || 1,
      filterDto.limit || 10,
      'Audit logs retrieved successfully',
    );
  }
}
