import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Delete,
  Query,
  UseGuards,
  NotFoundException,
  Patch,
} from '@nestjs/common';
import { RoleService } from '../services/role.service';
import { Role } from '../entities/role.entity';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { PermissionsGuard } from '../guards/permissions.guard';
import { RequirePermissions } from '../decorators/permissions.decorator';
import { PermissionModule } from '../entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';
import { ApiResponse } from 'src/common/interfaces/api-response.interface';
import { ResponseUtil } from 'src/common/utils/response.util';
import { FilterRoleDto } from '../dto/filter-role.dto';

@Controller('api/v1/roles')
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class RoleController {
  constructor(private readonly roleService: RoleService) {}

  @Get()
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'read',
  })
  async findAll(
    @Query() filterDto: FilterRoleDto,
  ): Promise<ApiResponse<Role[]>> {
    const [result, total] = await this.roleService.findAll(
      filterDto.page,
      filterDto.limit,
      filterDto.getAll,
    );

    if (filterDto.getAll) {
      return ResponseUtil.success(result, 'All roles retrieved successfully');
    }

    return ResponseUtil.paginated(
      result,
      total,
      filterDto.page,
      filterDto.limit,
      'Roles retrieved successfully',
    );
  }

  @Get('permissions')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'read',
  })
  async findAllPermissions() {
    const permissions = await this.roleService.findAllPermissions();

    return ResponseUtil.success(
      permissions,
      'Permissions retrieved successfully',
    );
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'read',
  })
  async findOne(@Param('id') id: string): Promise<ApiResponse<Role>> {
    const role = await this.roleService.findOne(id);

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return ResponseUtil.success(role, 'Role retrieved successfully');
  }

  @Post()
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'Role created successfully',
    resourceType: 'role',
    getResourceId: (result: Role) => result.id?.toString(),
  })
  async create(
    @Body() createRoleDto: CreateRoleDto,
  ): Promise<ApiResponse<Role | null>> {
    const role = await this.roleService.create(createRoleDto);
    if (!role) {
      return ResponseUtil.error('Role creation failed');
    }

    return ResponseUtil.created(role, 'Role created successfully');
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Role updated successfully',
    resourceType: 'role',
    getResourceId: (result: Role) => result.id?.toString(),
  })
  async update(
    @Param('id') id: string,
    @Body() updateRoleDto: UpdateRoleDto,
  ): Promise<ApiResponse<Role>> {
    const role = await this.roleService.update(id, updateRoleDto);

    if (!role) {
      throw new NotFoundException('Role not found');
    }

    return ResponseUtil.updated(role, 'Role updated successfully');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.ROLES,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'Role deleted successfully',
    resourceType: 'role',
    getResourceId: (result: Role) => result.id?.toString(),
  })
  async remove(@Param('id') id: string): Promise<ApiResponse<null>> {
    const deleted = await this.roleService.remove(id);

    if (!deleted) {
      throw new NotFoundException('Role not found');
    }

    return ResponseUtil.deleted('Role deleted successfully');
  }
}
