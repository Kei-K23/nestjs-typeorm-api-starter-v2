import { IsInt, IsOptional, IsString, MaxLength, Min } from 'class-validator';
import { Transform } from 'class-transformer';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterBannerDto extends PaginationFilterDto {
  @IsOptional()
  @IsString()
  search?: string;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  type?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  @Transform(({ value }) => {
    if (value === undefined || value === null || value === '') return undefined;
    const num = Number(value);
    return Number.isNaN(num) ? undefined : num;
  })
  minOrderIndex?: number;
}
