import { Transform } from 'class-transformer';
import { IsOptional, IsString, IsBoolean, IsIn } from 'class-validator';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';
import { UserType } from '../entities/user.entity';

export class FilterUserDto extends PaginationFilterDto {
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
  @IsString({ message: 'User type must be a string' })
  @IsIn(Object.values(UserType), {
    message: 'User type must be student, teacher, or parent',
  })
  userType?: UserType;
}
