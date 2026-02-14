import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  Patch,
  Post,
  Query,
  UseGuards,
  UsePipes,
  ValidationPipe,
} from '@nestjs/common';
import { JwtAuthGuard } from 'src/v1/auth/guards/jwt-auth.guard';
import { PermissionsGuard } from 'src/v1/auth/guards/permissions.guard';
import { RequirePermissions } from 'src/v1/auth/decorators/permissions.decorator';
import { PermissionModule } from 'src/v1/auth/entities/permission.entity';
import { LogActivity } from 'src/v1/activity-log/decorators/log-activity.decorator';
import { ActivityAction } from 'src/v1/activity-log/entities/user-activity-log.entity';
import { ResponseUtil } from 'src/common/utils/response.util';
import { FaqService } from '../services/faq.service';
import { CreateFaqDto } from '../dto/create-faq.dto';
import { UpdateFaqDto } from '../dto/update-faq.dto';
import { FilterFaqDto } from '../dto/filter-faq.dto';
import { Faq } from '../entities/faq.entity';

@Controller('api/v1/settings/faqs')
@UsePipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }))
@UseGuards(JwtAuthGuard, PermissionsGuard)
export class FaqController {
  constructor(private readonly faqService: FaqService) {}

  @Post()
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'create',
  })
  @LogActivity({
    action: ActivityAction.CREATE,
    description: 'FAQ created successfully',
    resourceType: 'faq',
    getResourceId: (result: Faq) => result.id?.toString(),
  })
  async create(@Body() createDto: CreateFaqDto) {
    const faq = await this.faqService.create(createDto);
    return ResponseUtil.created(faq, 'FAQ created successfully');
  }

  @Get()
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'read',
  })
  async findAll(@Query() filters: FilterFaqDto) {
    const result = await this.faqService.findAll(filters);

    if (filters.getAll) {
      return ResponseUtil.success(
        result.data,
        'All FAQs retrieved successfully',
      );
    }

    return ResponseUtil.paginated(
      result.data,
      result.total,
      result.page,
      result.limit,
      'FAQs retrieved successfully',
    );
  }

  @Patch(':id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'update',
  })
  @LogActivity({
    action: ActivityAction.UPDATE,
    description: 'FAQ updated successfully',
    resourceType: 'faq',
    getResourceId: (params: { id: string }) => params.id,
  })
  async update(@Param('id') id: string, @Body() updateDto: UpdateFaqDto) {
    const faq = await this.faqService.update(id, updateDto);
    return ResponseUtil.updated(faq, 'FAQ updated successfully');
  }

  @Delete(':id')
  @RequirePermissions({
    module: PermissionModule.SETTINGS,
    permission: 'delete',
  })
  @LogActivity({
    action: ActivityAction.DELETE,
    description: 'FAQ deleted successfully',
    resourceType: 'faq',
    getResourceId: (params: { id: string }) => params.id,
  })
  async remove(@Param('id') id: string) {
    const result = await this.faqService.remove(id);
    return ResponseUtil.success(result, 'FAQ deleted successfully');
  }
}
