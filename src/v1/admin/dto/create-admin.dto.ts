import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsUUID,
  IsIn,
} from 'class-validator';

export class CreateAdminDto {
  @IsString({ message: 'Full name must be a string' })
  @IsNotEmpty({ message: 'Full name is required' })
  @MinLength(2, { message: 'Full name must be at least 2 characters long' })
  @MaxLength(100, { message: 'Full name must not exceed 100 characters' })
  fullName: string;

  @IsEmail({}, { message: 'Please provide a valid email address' })
  @IsNotEmpty({ message: 'Email is required' })
  email: string;

  @IsString({ message: 'Phone must be a string' })
  @IsNotEmpty({ message: 'Phone is required' })
  phone: string;

  @IsOptional()
  @IsString({ message: 'Password must be a string' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password?: string;

  @IsOptional()
  @IsString({ message: 'Date of birth must be a string' })
  dateOfBirth?: string;

  @IsOptional()
  @IsString({ message: 'Gender must be a string' })
  @IsIn(['male', 'female'], { message: 'Gender must be either male or female' })
  gender?: string;

  @IsUUID('4', { message: 'Role ID must be a valid UUID' })
  @IsNotEmpty({ message: 'Role ID is required' })
  roleId: string;

  @IsOptional()
  @Transform(({ value }) => {
    if (value === undefined || value === null) return undefined;
    if (value === 'true' || value === '1' || value === true) return true;
    if (value === 'false' || value === '0' || value === false) return false;
    return undefined;
  })
  isBanned?: boolean;

  @IsOptional()
  @IsString({ message: 'Profile image URL must be a string' })
  profileImageUrl?: string;
}
