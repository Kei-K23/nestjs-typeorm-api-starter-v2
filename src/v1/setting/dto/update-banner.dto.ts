import { IsInt, IsOptional, IsString, MaxLength, Min } from 'class-validator';

export class UpdateBannerDto {
  @IsOptional()
  @IsString()
  imageUrl?: string;

  @IsOptional()
  @IsInt()
  @Min(0)
  orderIndex?: number;

  @IsOptional()
  @IsString()
  @MaxLength(50)
  type?: string;
}
