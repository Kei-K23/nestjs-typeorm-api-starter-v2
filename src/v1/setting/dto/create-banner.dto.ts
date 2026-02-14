import { Type } from 'class-transformer';
import {
  IsIn,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  Min,
} from 'class-validator';

export class CreateBannerDto {
  @IsString()
  @IsOptional()
  imageUrl: string;

  @Type(() => Number)
  @IsInt()
  @Min(0)
  orderIndex: number;

  @IsString()
  @IsNotEmpty()
  @MaxLength(50)
  @IsIn(['announcement', 'ads'])
  type: string;
}
