import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UploadedFile,
  UseGuards,
  UseInterceptors,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { AdminService } from '../services/admin.service';
import { Admin } from '../entities/admin.entity';
import { CreateAdminDto } from '../dto/create-admin.dto';
import { UpdateAdminDto } from '../dto/update-admin.dto';
import { FilterAdminDto } from '../dto/filter-admin.dto';

@Controller({ path: 'admins', version: '1' })
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class AdminController {
  constructor(private readonly adminService: AdminService) {}

  @Post()
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'create',
    },
    {
      module: PermissionModule.ADMIN_LIST,
      permission: 'create',
    },
  ])
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'Admin created successfully',
    resourceType: 'admin',
    getResourceId: (result: Admin) => result.id?.toString(),
  })
  @UseInterceptors(
    FileInterceptor('profileImage', {
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  async create(
    @UploadedFile() file: Express.Multer.File,
    @Body() createAdminDto: CreateAdminDto,
  ) {
    const admin = await this.adminService.create(createAdminDto, file);
    return ResponseUtil.created(admin, 'Admin created successfully');
  }

  @Get()
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'read',
    },
    {
      module: PermissionModule.ADMIN_LIST,
      permission: 'read',
    },
  ])
  async findAll(@Query() filters: FilterAdminDto) {
    const result = await this.adminService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All admins retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Admins retrieved successfully',
    );
  }

  @Get('/:id')
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'read',
    },
    {
      module: PermissionModule.ADMIN_LIST,
      permission: 'read',
    },
  ])
  async findOne(@Param('id') id: string) {
    const admin = await this.adminService.findOne(id);
    return ResponseUtil.success(
      admin,
      `Admin retrieved by ID ${id} successfully`,
    );
  }

  @Patch('/:id')
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'update',
    },
    {
      module: PermissionModule.ADMIN_LIST,
      permission: 'update',
    },
  ])
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Admin updated successfully',
    resourceType: 'admin',
    getResourceId: (result: Admin) => result.id?.toString(),
  })
  @UseInterceptors(
    FileInterceptor('profileImage', {
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  async update(
    @Param('id') id: string,
    @UploadedFile() file: Express.Multer.File,
    @Body() updateAdminDto: UpdateAdminDto,
  ) {
    const admin = await this.adminService.update(id, updateAdminDto, file);
    return ResponseUtil.updated(admin, 'Admin updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions([
    {
      module: PermissionModule.ADMIN,
      permission: 'delete',
    },
    {
      module: PermissionModule.ADMIN_LIST,
      permission: 'delete',
    },
  ])
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'Admin deleted successfully',
    resourceType: 'admin',
    getResourceId: (params: { id: string }) => params.id,
  })
  async remove(@Param('id') id: string) {
    const result = await this.adminService.remove(id);
    return ResponseUtil.success(result, 'Admin deleted successfully');
  }
}
