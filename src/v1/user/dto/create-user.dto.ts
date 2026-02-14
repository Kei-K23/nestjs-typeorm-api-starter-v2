import { Transform } from 'class-transformer';
import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsIn,
} from 'class-validator';
import { UserType } from '../entities/user.entity';

export class CreateUserDto {
  @IsOptional()
  @IsEmail({}, { message: 'Please provide a valid email address' })
  email?: string;

  @IsString({ message: 'Full name must be a string' })
  @IsNotEmpty({ message: 'Full name is required' })
  @MinLength(2, { message: 'Full name must be at least 2 characters long' })
  @MaxLength(100, { message: 'Full name must not exceed 100 characters' })
  fullName: string;

  @IsString({ message: 'Password must be a string' })
  @IsNotEmpty({ message: 'Password is required' })
  @MinLength(8, { message: 'Password must be at least 8 characters long' })
  password: string;

  @IsString({ message: 'Phone must be a string' })
  @IsNotEmpty({ message: 'Phone is required' })
  phone: string;

  @IsOptional()
  @IsString({ message: 'Date of birth must be a string' })
  dateOfBirth?: string;

  @IsOptional()
  @IsString({ message: 'Gender must be a string' })
  @IsIn(['male', 'female'], { message: 'Gender must be either male or female' })
  gender?: string;

  @IsString({ message: 'User type must be a string' })
  @IsIn(['student', 'teacher', 'parent'], {
    message: 'User type must be student, teacher, or parent',
  })
  userType: UserType;

  @IsOptional()
  @IsString({ message: 'Preferred language must be a string' })
  @IsIn(['myanmar', 'english'], {
    message: 'Preferred language must be myanmar or english',
  })
  preferLanguage?: string;

  @IsString({ message: 'Division must be a string' })
  @IsNotEmpty({ message: 'Division is required' })
  division: string;

  @IsString({ message: 'City must be a string' })
  @IsNotEmpty({ message: 'City is required' })
  city: string;

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
