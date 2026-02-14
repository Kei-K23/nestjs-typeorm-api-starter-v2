import { Transform } from 'class-transformer';
import { IsOptional, IsString, IsBoolean, IsUUID } from 'class-validator';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterAdminDto extends PaginationFilterDto {
  @IsOptional()
  @IsString({ message: 'Search must be a string' })
  search?: string;

  @IsOptional()
  @IsBoolean({ message: 'Is banned must be a boolean' })
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isBanned?: boolean;

  @IsOptional()
  @IsString({ message: 'Role ID must be a string' })
  @IsUUID('4', { message: 'Role ID must be a valid UUID' })
  @Transform(({ value }) => value?.trim() || undefined)
  roleId?: string;
}
