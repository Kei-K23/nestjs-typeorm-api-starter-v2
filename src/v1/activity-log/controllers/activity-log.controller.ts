import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { ActivityLogService } from '../services/activity-log.service';
import { AuditLogService } from '../services/audit-log.service';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';
import { FilterAuditLogDto } from '../dto/filter-audit-log.dto';
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { ResolvePresignedUrls } from 'src/common/decorators/presigned-urls.decorator';

@Controller({ path: '/', version: '1' })
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class ActivityLogController {
  constructor(
    private readonly activityLogService: ActivityLogService,
    private readonly auditLogService: AuditLogService,
  ) {}

  @Get('user-logs')
  @ResolvePresignedUrls('user.profileImageUrl')
  @RequirePermissions(
    { module: PermissionModule.ADMIN, permission: 'read' },
    { module: PermissionModule.ADMIN_USER_LOGS, permission: 'read' },
  )
  async findAllUserLogs(@Query() filterDto: FilterActivityLogDto) {
    const result = await this.activityLogService.findAll(filterDto);

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
  @ResolvePresignedUrls('admin.profileImageUrl')
  @RequirePermissions(
    { module: PermissionModule.ADMIN, permission: 'read' },
    { module: PermissionModule.ADMIN_AUDIT_LOGS, permission: 'read' },
  )
  async findAllAuditLogs(@Query() filterDto: FilterAuditLogDto) {
    const result = await this.auditLogService.findAll(filterDto);

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
