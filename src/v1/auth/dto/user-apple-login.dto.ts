import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UserAppleLoginDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsOptional()
  fcmToken?: string;
}
