import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import {
  Repository,
  Between,
  FindManyOptions,
  FindOptionsWhere,
  IsNull,
} from 'typeorm';
import { UserActivityLog } from '../entities/user-activity-log.entity';
import { FilterActivityLogDto } from '../dto/filter-activity-log.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';

@Injectable()
export class ActivityLogService {
  constructor(
    @InjectRepository(UserActivityLog)
    private readonly activityLogRepository: Repository<UserActivityLog>,
    private readonly s3ClientUtils: S3ClientUtils,
  ) {}

  async create(createActivityLogDto: any) {
    const activityLog = this.activityLogRepository.create(createActivityLogDto);
    return await this.activityLogRepository.save(activityLog);
  }

  async findAll(filterDto: FilterActivityLogDto) {
    const {
      userId,
      adminId,
      userType,
      action,
      resourceType,
      resourceId,
      ipAddress,
      device,
      location,
      startDate,
      endDate,
      isActivityLog,
      page = 1,
      limit = 10,
    } = filterDto;

    const whereConditions: FindOptionsWhere<UserActivityLog> = {};

    if (isActivityLog !== undefined) {
      whereConditions.isActivityLog = isActivityLog;
    }
    if (userId) {
      whereConditions.userId = userId;
    }
    if (adminId) {
      whereConditions.adminId = adminId;
    }
    if (action) {
      whereConditions.action = action;
    }
    if (resourceType) {
      whereConditions.resourceType = resourceType;
    }
    if (resourceId) {
      whereConditions.resourceId = resourceId;
    }
    if (ipAddress) {
      whereConditions.ipAddress = ipAddress;
    }
    if (device) {
      whereConditions.device = device;
    }
    if (location) {
      whereConditions.location = location;
    }

    if (userType === 'USER') {
      whereConditions.adminId = IsNull();
    } else if (userType === 'ADMIN') {
      whereConditions.userId = IsNull();
    }

    if (startDate && endDate) {
      whereConditions.createdAt = Between(
        new Date(startDate),
        new Date(endDate),
      );
    } else if (startDate) {
      whereConditions.createdAt = Between(new Date(startDate), new Date());
    }

    const options: FindManyOptions<UserActivityLog> = {
      where: whereConditions,
      relations: ['user', 'admin'],
      skip: (page - 1) * limit,
      take: limit,
      order: {
        createdAt: 'DESC',
      },
    };

    const [data, total] =
      await this.activityLogRepository.findAndCount(options);

    const dataWithUserImage = await Promise.all(
      data.map(async (d) => ({
        ...d,
        user: {
          ...d.user,
          profileImageUrl: d.user?.profileImageUrl
            ? await this.s3ClientUtils.generatePresignedUrl(
                d.user.profileImageUrl,
              )
            : null,
        },
      })),
    );

    return {
      data: dataWithUserImage,
      total,
    };
  }

  async deleteOldLogs(daysToKeep: number = 90): Promise<void> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

    await this.activityLogRepository
      .createQueryBuilder()
      .delete()
      .where('createdAt < :cutoffDate', { cutoffDate })
      .execute();
  }
}
