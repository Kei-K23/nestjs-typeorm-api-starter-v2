import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { randomUUID } from 'crypto';
import { Repository } from 'typeorm';
import { User } from '../entities/user.entity';
import { CreateUserDto } from '../dto/create-user.dto';
import { FilterUserDto } from '../dto/filter-user.dto';
import { UpdateUserDto } from '../dto/update-user.dto';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';

@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);

  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private s3ClientUtils: S3ClientUtils,
  ) {}

  async create(createUserDto: CreateUserDto, file?: Express.Multer.File) {
    const existingPhoneUser = await this.userRepository.findOne({
      where: { phone: createUserDto.phone },
    });

    if (existingPhoneUser) {
      throw new ConflictException(
        `User with phone '${createUserDto.phone}' already exists`,
      );
    }

    let profileImageUrl = createUserDto.profileImageUrl || '';

    if (file) {
      const original = file.originalname?.trim() || 'profile';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;
      const res = await this.s3ClientUtils.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: 'users/profile',
        metadata: { filename: original },
      });
      if (res.success && res.key) {
        profileImageUrl = res.key;
      }
    }

    const user = this.userRepository.create({
      ...createUserDto,
      profileImageUrl,
    });
    const savedUser = await this.userRepository.save(user);
    this.logger.log(`User created with ID: ${savedUser.id}`);

    return savedUser;
  }

  async findAll(filter: FilterUserDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.userRepository
      .createQueryBuilder('user')
      .orderBy('user.createdAt', 'DESC');

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    if (filter.search) {
      qb.andWhere('(user.fullName ILIKE :term OR user.email ILIKE :term)', {
        term: `%${filter.search}%`,
      });
    }

    if (filter.isBanned !== undefined) {
      qb.andWhere('user.isBanned = :isBanned', { isBanned: filter.isBanned });
    }

    if (filter.userType) {
      qb.andWhere('user.userType = :userType', { userType: filter.userType });
    }

    const [data, total] = await qb.getManyAndCount();

    // Add presigned URL to each user
    const usersWithPresignedUrl = await Promise.all(
      data.map(async (user) => {
        user.profileImageUrl =
          (await this.s3ClientUtils.generatePresignedUrl(
            user.profileImageUrl || '',
          )) || '';
        return user;
      }),
    );

    return {
      data: usersWithPresignedUrl,
      total,
      page,
      limit,
    };
  }

  async findOne(id: string) {
    const user = await this.userRepository.findOne({
      where: { id },
    });
    if (!user) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    // Add presigned URL to user
    user.profileImageUrl =
      (await this.s3ClientUtils.generatePresignedUrl(
        user.profileImageUrl || '',
      )) || '';

    return user;
  }

  async update(
    id: string,
    updateUserDto: UpdateUserDto,
    file?: Express.Multer.File,
  ) {
    // Check if user exists
    const existingUser = await this.userRepository.findOne({ where: { id } });

    if (!existingUser) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    if (updateUserDto.phone && updateUserDto.phone !== existingUser.phone) {
      const duplicatePhoneUser = await this.userRepository.findOne({
        where: { phone: updateUserDto.phone },
      });
      if (duplicatePhoneUser) {
        this.logger.warn(
          `User with phone '${updateUserDto.phone}' already exists`,
        );
        throw new ConflictException(
          `User with phone '${updateUserDto.phone}' already exists`,
        );
      }
    }

    const hasBodyProfileImageUrl =
      typeof updateUserDto.profileImageUrl === 'string' &&
      updateUserDto.profileImageUrl.length >= 0;

    let newProfileImageUrl = existingUser.profileImageUrl || '';

    if (file) {
      const original = file.originalname?.trim() || 'profile';
      const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const key = `${randomUUID()}-${sanitized}`;
      const res = await this.s3ClientUtils.uploadFile({
        key,
        body: file.buffer,
        contentType: file.mimetype,
        path: 'users/profile',
        metadata: { filename: original },
      });
      if (res.success && res.key) {
        newProfileImageUrl = res.key;
      }
    } else if (hasBodyProfileImageUrl) {
      newProfileImageUrl = updateUserDto.profileImageUrl || '';
    }

    const updatedUser = await this.userRepository.preload({
      id,
      ...updateUserDto,
      profileImageUrl: newProfileImageUrl,
    });

    if (!updatedUser) {
      this.logger.warn(`User with ID '${id}' not found`);
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    if (updateUserDto.password) {
      updatedUser.password = updateUserDto.password;
    }

    const savedUser = await this.userRepository.save(updatedUser);

    const imageChanged =
      newProfileImageUrl !== (existingUser.profileImageUrl || '');

    if (imageChanged && existingUser.profileImageUrl) {
      await this.s3ClientUtils.deleteObject(existingUser.profileImageUrl);
    }
    this.logger.log(`User updated with ID: ${savedUser.id}`);

    return savedUser;
  }

  async remove(id: string) {
    const existingUser = await this.userRepository.findOne({
      where: { id },
    });
    if (!existingUser) {
      throw new NotFoundException(`User with ID '${id}' not found`);
    }

    if (existingUser.profileImageUrl) {
      await this.s3ClientUtils.deleteObject(existingUser.profileImageUrl);
    }

    await this.userRepository.softRemove(existingUser);
    this.logger.log(`User with ID '${id}' has been successfully soft deleted`);

    return {
      message: `User with ID '${id}' has been successfully deleted`,
    };
  }
}
