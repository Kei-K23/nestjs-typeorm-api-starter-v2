import { IsEmail, IsIn, IsNotEmpty } from 'class-validator';

export class ForgotPasswordSendOTPDto {
  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsNotEmpty({ message: 'User type is required' })
  @IsIn(['USER', 'ADMIN'], { message: 'Invalid user type' })
  userType: 'USER' | 'ADMIN';
}
