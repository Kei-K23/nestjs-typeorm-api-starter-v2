import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class ResetPasswordDto {
  @IsString({ message: 'Access Token must be a string' })
  @IsNotEmpty({ message: 'Access Token is required' })
  accessToken: string;

  @IsString({ message: 'New password must be a string' })
  @IsNotEmpty({ message: 'New password is required' })
  @MinLength(6, { message: 'New password must be at least 6 characters long' })
  newPassword: string;
}
