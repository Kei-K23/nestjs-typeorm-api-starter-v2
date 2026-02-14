import { IsOptional, IsString, MaxLength } from 'class-validator';

export class UpdateFaqDto {
  @IsOptional()
  @IsString()
  @MaxLength(255)
  question?: string;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  answer?: string;
}
