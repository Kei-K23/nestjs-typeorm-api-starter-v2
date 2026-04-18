import { IsNotEmpty, IsString, Matches, MaxLength } from 'class-validator';

export class UserLoginDto {
  @IsString({ message: 'Phone must be a string' })
  @IsNotEmpty({ message: 'Phone is required' })
  @Matches(/^09\d{7,9}$/, {
    message: 'Phone number must start with 09 and be followed by 7 to 9 digits',
  })
  phone: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MaxLength(128, { message: 'Password must not exceed 128 characters' })
  password: string;

  @IsString({ message: 'FCM token must be a string' })
  @IsNotEmpty({ message: 'FCM token is required' })
  fcmToken: string;
}
