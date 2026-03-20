import {
  IsOptional,
  IsEnum,
  IsString,
  IsDateString,
  IsBoolean,
  IsNotEmpty,
  IsIn,
} from 'class-validator';
import { ActivityAction } from '../entities/user-activity-log.entity';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';
import { Transform } from 'class-transformer';

export class FilterActivityLogDto extends PaginationFilterDto {
  @IsOptional()
  @IsString()
  userId?: string;

  @IsNotEmpty({ message: 'User type is required' })
  @IsIn(['USER', 'ADMIN'], { message: 'Invalid user type' })
  userType: 'USER' | 'ADMIN';

  @IsOptional()
  @IsString()
  adminId?: string;

  @IsOptional()
  @IsEnum(ActivityAction)
  action?: ActivityAction;

  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isActivityLog?: boolean;

  @IsOptional()
  @IsString()
  resourceType?: string;

  @IsOptional()
  @IsString()
  resourceId?: string;

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
  @IsDateString()
  startDate?: string;

  @IsOptional()
  @IsDateString()
  endDate?: string;

  @IsOptional()
  @IsString()
  sortBy?: string = 'createdAt';

  @IsOptional()
  @IsString()
  sortOrder?: 'ASC' | 'DESC' = 'DESC';
}
