import { IsNotEmpty, IsString, IsUUID } from 'class-validator';

export class VerifyPasswordResetOTPCodeDto {
  @IsUUID()
  @IsString()
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @IsString({ message: 'Verification code must be a string' })
  @IsNotEmpty({ message: 'Verification code is required' })
  code: string;
}
