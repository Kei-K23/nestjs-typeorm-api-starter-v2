import {
  IsOptional,
  IsEnum,
  IsString,
  IsDateString,
  IsIn,
} from 'class-validator';
import { LogAction } from '../constants/log-action.enum';
import { LogStatus } from '../constants/log-status.enum';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterAuditLogDto extends PaginationFilterDto {
  @IsOptional()
  @IsString()
  adminId?: string;

  @IsOptional()
  @IsEnum(LogAction)
  action?: LogAction;

  @IsOptional()
  @IsString()
  entityName?: string;

  @IsOptional()
  @IsString()
  entityId?: string;

  @IsOptional()
  @IsString()
  ipAddress?: string;

  @IsOptional()
  @IsString()
  device?: string;

  @IsOptional()
  @IsString()
  location?: string;

  @IsOptional()
  @IsEnum(LogStatus)
  status?: LogStatus;

  @IsOptional()
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @IsOptional()
  @IsIn(['ASC', 'DESC'])
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}
