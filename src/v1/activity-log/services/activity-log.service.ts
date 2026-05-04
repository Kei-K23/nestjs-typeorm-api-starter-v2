import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  Between,
  FindManyOptions,
  FindOptionsWhere,
  Repository,
} from 'typeorm';
import { ActivityLog } from '../entities/activity-log.entity';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';
import { CreateActivityLogData } from '../interfaces/create-activity-log.interface';

const VALID_SORT_FIELDS: (keyof ActivityLog)[] = [
  'createdAt',
  'action',
  'resourceType',
];

@Injectable()
export class ActivityLogService {
  constructor(
    @InjectRepository(ActivityLog)
    private readonly activityLogRepository: Repository<ActivityLog>,
  ) {}

  async create(data: CreateActivityLogData): Promise<ActivityLog> {
    const log = this.activityLogRepository.create(data);
    return this.activityLogRepository.save(log);
  }

  async findAll(
    filterDto: FilterActivityLogDto,
  ): Promise<{ data: ActivityLog[]; total: number }> {
    const {
      userId,
      action,
      resourceType,
      resourceId,
      ipAddress,
      device,
      location,
      status,
      startDate,
      endDate,
      sortBy = 'createdAt',
      sortOrder = 'DESC',
      page = 1,
      limit = 10,
      getAll = false,
    } = filterDto;

    const where: FindOptionsWhere<ActivityLog> = {};

    if (userId) where.userId = userId;
    if (action) where.action = action;
    if (resourceType) where.resourceType = resourceType;
    if (resourceId) where.resourceId = resourceId;
    if (ipAddress) where.ipAddress = ipAddress;
    if (device) where.device = device;
    if (location) where.location = location;
    if (status) where.status = status;

    if (startDate && endDate) {
      where.createdAt = Between(new Date(startDate), new Date(endDate));
    } else if (startDate) {
      where.createdAt = Between(new Date(startDate), new Date());
    }

    const orderField = VALID_SORT_FIELDS.includes(sortBy as keyof ActivityLog)
      ? (sortBy as keyof ActivityLog)
      : 'createdAt';

    const options: FindManyOptions<ActivityLog> = {
      where,
      relations: ['user'],
      order: { [orderField]: sortOrder },
      ...(getAll ? {} : { skip: (page - 1) * limit, take: limit }),
    };

    const [data, total] =
      await this.activityLogRepository.findAndCount(options);
    return { data, total };
  }

  async deleteOldLogs(daysToKeep: number = 90): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    await this.activityLogRepository
      .createQueryBuilder()
      .delete()
      .where('"createdAt" < :cutoffDate', { cutoffDate })
      .execute();
  }
}
