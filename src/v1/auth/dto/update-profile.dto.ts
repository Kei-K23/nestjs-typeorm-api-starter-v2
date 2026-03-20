import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from 'src/v1/user/dto/create-user.dto';

export class UpdateProfileDto extends PartialType(CreateUserDto) {}
