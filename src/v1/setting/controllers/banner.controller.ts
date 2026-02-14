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
import { BannerService } from '../services/banner.service';
import { CreateBannerDto } from '../dto/create-banner.dto';
import { UpdateBannerDto } from '../dto/update-banner.dto';
import { FilterBannerDto } from '../dto/filter-banner.dto';
import { Banner } from '../entities/banner.entity';

@Controller('api/v1/settings/banners')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class BannerController {
  constructor(private readonly bannerService: BannerService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'Banner created successfully',
    resourceType: 'banner',
    getResourceId: (result: Banner) => result.id?.toString(),
  })
  @UseInterceptors(
    FileInterceptor('image', {
      limits: { fileSize: 10 * 1024 * 1024 },
      fileFilter: (_req, file, cb) => {
        if (!file?.mimetype) return cb(null, false);
        cb(null, true);
      },
    }),
  )
  async create(
    @UploadedFile() file: Express.Multer.File,
    @Body() createDto: CreateBannerDto,
  ) {
    const banner = await this.bannerService.create(createDto, file);
    return ResponseUtil.created(banner, 'Banner created successfully');
  }

  @Get()
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  async findAll(@Query() filters: FilterBannerDto) {
    const result = await this.bannerService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All banners retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'Banners retrieved successfully',
    );
  }

  @Get(':id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  async findOne(@Param('id') id: string) {
    const banner = await this.bannerService.findOne(id);
    return ResponseUtil.success(
      banner,
      `Banner retrieved by ID ${id} successfully`,
    );
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'Banner updated successfully',
    resourceType: 'banner',
    getResourceId: (params: { id: string }) => params.id,
  })
  @UseInterceptors(
    FileInterceptor('image', {
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
    @Body() updateDto: UpdateBannerDto,
  ) {
    const banner = await this.bannerService.update(id, updateDto, file);
    return ResponseUtil.updated(banner, 'Banner updated successfully');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'Banner deleted successfully',
    resourceType: 'banner',
    getResourceId: (params: { id: string }) => params.id,
  })
  async remove(@Param('id') id: string) {
    const result = await this.bannerService.remove(id);
    return ResponseUtil.success(result, 'Banner deleted successfully');
  }
}
