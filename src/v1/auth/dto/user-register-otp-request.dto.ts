import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class UserRegisterOTPRequestDto {
  @IsString({ message: 'Phone must be a string' })
  @IsNotEmpty({ message: 'Phone is required' })
  @Matches(/^09\d{7,9}$/, {
    message: 'Phone number must start with 09 and be followed by 7 to 9 digits',
  })
  phone: string;
}
