import {
  IsIn,
  IsNotEmpty,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  MinLength,
} from 'class-validator';
import { UserType } from 'src/v1/user/entities/user.entity';

export class UserRegisterAccountSetupDto {
  @IsOptional()
  @IsString()
  email?: string;

  @IsString({ message: 'Full name must be a string' })
  @IsNotEmpty({ message: 'Full name is required' })
  @MinLength(2, { message: 'Full name must be at least 2 characters long' })
  @MaxLength(100, { message: 'Full name must not exceed 100 characters' })
  fullName: string;

  @IsString({ message: 'User ID must be a string' })
  @IsUUID('4', { message: 'User ID must be a valid UUID v4' })
  @IsNotEmpty({ message: 'User ID is required' })
  userId: string;

  @IsString({ message: 'Date of birth must be a string' })
  dateOfBirth: string;

  @IsOptional()
  @IsString({ message: 'Gender must be a string' })
  @IsIn(['male', 'female'], { message: 'Gender must be either male or female' })
  gender?: string;

  @IsOptional()
  @IsString({ message: 'User type must be a string' })
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
  @IsString({ message: 'Profile image URL must be a string' })
  profileImageUrl?: string;

  @IsOptional()
  @IsString({ message: 'FCM token must be a string' })
  fcmToken?: string;
}
