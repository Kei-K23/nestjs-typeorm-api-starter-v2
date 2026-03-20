import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UserGoogleLoginDto {
  @IsString()
  @IsNotEmpty()
  token: string;

  @IsString()
  @IsOptional()
  fcmToken?: string;
}
