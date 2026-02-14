import { IsOptional, IsString } from 'class-validator';
import { PaginationFilterDto } from 'src/common/dto/pagination-filter.dto';

export class FilterFaqDto extends PaginationFilterDto {
  @IsOptional()
  @IsString()
  search?: string;
}
