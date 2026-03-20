import { IsNotEmpty, IsOptional, IsString } from 'class-validator';

export class UserGoogleLoginDto {
  @IsString({ message: 'Token must be a string' })
  @IsNotEmpty({ message: 'Token is required' })
  token: string;

  @IsOptional()
  @IsString({ message: 'FCM Token must be a string' })
  fcmToken?: string;
}
