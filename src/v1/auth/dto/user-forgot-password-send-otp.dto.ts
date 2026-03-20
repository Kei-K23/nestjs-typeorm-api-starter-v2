import { IsNotEmpty, IsString } from 'class-validator';

export class UserForgotPasswordSendOTPDto {
  @IsString({ message: 'Phone number must be a string' })
  @IsNotEmpty({ message: 'Phone number is required' })
  phone: string;
}
