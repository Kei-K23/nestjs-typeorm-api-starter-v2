import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Between, FindManyOptions, FindOptionsWhere, Repository } from 'typeorm';
import { AuditLog } from '../entities/audit-log.entity';
import { FilterAuditLogDto } from '../dto/filter-audit-log.dto';
import { CreateAuditLogData } from '../interfaces/create-audit-log.interface';
import {
  nowUtc,
  parseRangeStart,
  parseRangeEnd,
  subtractDays,
  LOG_RETENTION_DAYS,
} from 'src/common/utils/date-time.util';

const VALID_SORT_FIELDS: (keyof AuditLog)[] = [
  'createdAt',
  'action',
  'entityName',
];

@Injectable()
export class AuditLogService {
  constructor(
    @InjectRepository(AuditLog)
    private readonly auditLogRepository: Repository<AuditLog>,
  ) {}

  async create(data: CreateAuditLogData): Promise<AuditLog> {
    const log = this.auditLogRepository.create(data);
    return this.auditLogRepository.save(log);
  }

  async findAll(
    filterDto: FilterAuditLogDto,
  ): Promise<{ data: AuditLog[]; total: number }> {
    const {
      adminId,
      action,
      entityName,
      entityId,
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

    const where: FindOptionsWhere<AuditLog> = {};

    if (adminId) where.adminId = adminId;
    if (action) where.action = action;
    if (entityName) where.entityName = entityName;
    if (entityId) where.entityId = entityId;
    if (ipAddress) where.ipAddress = ipAddress;
    if (device) where.device = device;
    if (location) where.location = location;
    if (status) where.status = status;

    if (startDate && endDate) {
      where.createdAt = Between(parseRangeStart(startDate), parseRangeEnd(endDate));
    } else if (startDate) {
      where.createdAt = Between(parseRangeStart(startDate), nowUtc());
    }

    const orderField = VALID_SORT_FIELDS.includes(sortBy as keyof AuditLog)
      ? (sortBy as keyof AuditLog)
      : 'createdAt';

    const options: FindManyOptions<AuditLog> = {
      where,
      relations: ['admin'],
      order: { [orderField]: sortOrder },
      ...(getAll ? {} : { skip: (page - 1) * limit, take: limit }),
    };

    const [data, total] = await this.auditLogRepository.findAndCount(options);
    return { data, total };
  }

  async deleteOldLogs(daysToKeep: number = LOG_RETENTION_DAYS): Promise<void> {
    const cutoffDate = subtractDays(daysToKeep);

    await this.auditLogRepository
      .createQueryBuilder()
      .delete()
      .where('"createdAt" < :cutoffDate', { cutoffDate })
      .execute();
  }
}
