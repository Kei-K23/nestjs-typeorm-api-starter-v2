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
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { UserService } from '../services/user.service';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { ResponseUtil } from 'src/common/utils/response.util';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';

@Controller('api/v1/users')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'User created successfully',
    resourceType: 'user',
    getResourceId: (result: User) => result.id?.toString(),
  })
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
  async create(
    @UploadedFile() file: Express.Multer.File,
    @Body() createUserDto: CreateUserDto,
  ) {
    const user = await this.userService.create(createUserDto, file);
    return ResponseUtil.created(user, 'User created successfully');
  }

  @Get()
  async findAll(@Query() filters: FilterUserDto) {
    const result = await this.userService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All users retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Users retrieved successfully',
    );
  }

  @Get('/:id')
  async findOne(@Param('id') id: string) {
    const user = await this.userService.findOne(id);
    return ResponseUtil.success(
      user,
      `User retrieved by ID ${id} successfully`,
    );
  }

  @Patch('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'User updated successfully',
    resourceType: 'user',
    getResourceId: (result: User) => result.id?.toString(),
  })
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
  async update(
    @Param('id') id: string,
    @UploadedFile() file: Express.Multer.File,
    @Body() updateUserDto: UpdateUserDto,
  ) {
    const user = await this.userService.update(id, updateUserDto, file);
    return ResponseUtil.updated(user, 'User updated successfully');
  }

  @Delete('/:id')
  @RequirePermissions({
    module: PermissionModule.USERS,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'User deleted successfully',
    resourceType: 'user',
    getResourceId: (params: { id: string }) => params.id,
  })
  async remove(@Param('id') id: string) {
    const result = await this.userService.remove(id);
    return ResponseUtil.success(result, 'User deleted successfully');
  }
}
