import {
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Admin } from '../entities/admin.entity';
import { CreateAdminDto } from '../dto/create-admin.dto';
import { UpdateAdminDto } from '../dto/update-admin.dto';
import { FilterAdminDto } from '../dto/filter-admin.dto';
import { Role } from 'src/v1/auth/entities/role.entity';
import { S3ClientUtils } from 'src/common/utils/s3-client.utils';
import { FileUploadService } from 'src/common/services/file-upload.service';
import { attachAuditLogMetadata } from 'src/v1/activity-log/utils/audit-log-metadata.util';

@Injectable()
export class AdminService {
  private readonly logger = new Logger(AdminService.name);

  constructor(
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    private s3ClientUtils: S3ClientUtils,
    private fileUploadService: FileUploadService,
  ) {}

  async create(createAdminDto: CreateAdminDto, file?: Express.Multer.File) {
    const existingEmailAdmin = await this.adminRepository.findOne({
      where: { email: createAdminDto.email },
    });

    if (existingEmailAdmin) {
      throw new ConflictException(
        `Admin with email '${createAdminDto.email}' already exists`,
      );
    }

    const role = await this.roleRepository.findOne({
      where: { id: createAdminDto.roleId },
    });
    if (!role) {
      throw new NotFoundException(
        `Role with ID '${createAdminDto.roleId}' not found`,
      );
    }

    let profileImageUrl = createAdminDto.profileImageUrl || '';

    if (file) {
      const uploadedKey = await this.fileUploadService.uploadProfileImage(
        file,
        'admins/profile',
      );
      if (uploadedKey) {
        profileImageUrl = uploadedKey;
      }
    }

    const admin = this.adminRepository.create({
      ...createAdminDto,
      profileImageUrl,
    });
    const savedAdmin = await this.adminRepository.save(admin);
    this.logger.log(`Admin created with ID: ${savedAdmin.id}`);

    return savedAdmin;
  }

  async findAll(filter: FilterAdminDto) {
    const { getAll, limit, page } = filter;
    const skip = (page - 1) * limit;

    const qb = this.adminRepository
      .createQueryBuilder('admin')
      .leftJoinAndSelect('admin.role', 'role')
      .orderBy('admin.createdAt', 'DESC');

    if (!getAll) {
      qb.skip(skip).take(limit);
    }

    if (filter.search) {
      qb.andWhere('(admin.fullName ILIKE :term OR admin.email ILIKE :term)', {
        term: `%${filter.search}%`,
      });
    }

    if (filter.roleId) {
      qb.andWhere('admin.roleId = :roleId', { roleId: filter.roleId });
    }

    if (filter.isBanned !== undefined) {
      qb.andWhere('admin.isBanned = :isBanned', { isBanned: filter.isBanned });
    }

    const [data, total] = await qb.getManyAndCount();

    return { data, total, page, limit };
  }

  async findOne(id: string) {
    const admin = await this.adminRepository.findOne({
      where: { id },
      relations: [
        'role',
        'role.rolePermissions',
        'role.rolePermissions.permission',
        'role.rolePermissions.permission.module',
      ],
    });
    if (!admin) {
      throw new NotFoundException(`Admin with ID '${id}' not found`);
    }

    return admin;
  }

  async update(
    id: string,
    updateAdminDto: UpdateAdminDto,
    file?: Express.Multer.File,
  ) {
    const existingAdmin = await this.adminRepository.findOne({ where: { id } });

    if (!existingAdmin) {
      throw new NotFoundException(`Admin with ID '${id}' not found`);
    }

    if (updateAdminDto.email && updateAdminDto.email !== existingAdmin.email) {
      const duplicateEmailAdmin = await this.adminRepository.findOne({
        where: { email: updateAdminDto.email },
      });
      if (duplicateEmailAdmin) {
        this.logger.warn(
          `Admin with email '${updateAdminDto.email}' already exists`,
        );
        throw new ConflictException(
          `Admin with email '${updateAdminDto.email}' already exists`,
        );
      }
    }

    if (
      updateAdminDto.roleId &&
      updateAdminDto.roleId !== existingAdmin.roleId
    ) {
      const role = await this.roleRepository.findOne({
        where: { id: updateAdminDto.roleId },
      });
      if (!role) {
        this.logger.warn(`Role with ID '${updateAdminDto.roleId}' not found`);
        throw new NotFoundException(
          `Role with ID '${updateAdminDto.roleId}' not found`,
        );
      }
    }

    const hasBodyProfileImageUrl =
      typeof updateAdminDto.profileImageUrl === 'string' &&
      updateAdminDto.profileImageUrl.length >= 0;

    let newProfileImageUrl = existingAdmin.profileImageUrl || '';

    if (file) {
      const uploadedKey = await this.fileUploadService.uploadProfileImage(
        file,
        'admins/profile',
      );
      if (uploadedKey) {
        newProfileImageUrl = uploadedKey;
      }
    } else if (hasBodyProfileImageUrl) {
      newProfileImageUrl = updateAdminDto.profileImageUrl || '';
    }

    const updatedAdmin = await this.adminRepository.preload({
      id,
      ...updateAdminDto,
      profileImageUrl: newProfileImageUrl,
    });

    if (!updatedAdmin) {
      this.logger.warn(`Admin with ID '${id}' not found`);
      throw new NotFoundException(`Admin with ID '${id}' not found`);
    }

    const savedAdmin = await this.adminRepository.save(updatedAdmin);

    const auditValues = this.getChangedAuditValues(existingAdmin, savedAdmin, [
      ...Object.keys(updateAdminDto),
      ...(file ? ['profileImageUrl'] : []),
    ]);
    attachAuditLogMetadata(savedAdmin, auditValues);

    const imageChanged =
      newProfileImageUrl !== (existingAdmin.profileImageUrl || '');

    if (imageChanged && existingAdmin.profileImageUrl) {
      await this.s3ClientUtils.deleteObject(existingAdmin.profileImageUrl);
    }
    this.logger.log(`Admin updated with ID: ${savedAdmin.id}`);

    return savedAdmin;
  }

  private getChangedAuditValues(
    oldAdmin: Admin,
    newAdmin: Admin,
    fields: string[],
  ): {
    oldValue: Record<string, unknown>;
    newValue: Record<string, unknown>;
  } {
    const oldValue: Record<string, unknown> = {};
    const newValue: Record<string, unknown> = {};
    const auditableFields = [...new Set(fields)].filter(
      (field) => field !== 'password',
    );

    for (const field of auditableFields) {
      const oldFieldValue = oldAdmin[field as keyof Admin] as unknown;
      const newFieldValue = newAdmin[field as keyof Admin] as unknown;

      if (oldFieldValue !== newFieldValue) {
        oldValue[field] = oldFieldValue;
        newValue[field] = newFieldValue;
      }
    }

    return { oldValue, newValue };
  }

  async remove(id: string) {
    const existingAdmin = await this.adminRepository.findOne({
      where: { id },
    });
    if (!existingAdmin) {
      throw new NotFoundException(`Admin with ID '${id}' not found`);
    }

    if (existingAdmin.profileImageUrl) {
      await this.s3ClientUtils.deleteObject(existingAdmin.profileImageUrl);
    }

    await this.adminRepository.softRemove(existingAdmin);
    this.logger.log(`Admin with ID '${id}' has been successfully soft deleted`);

    return {
      message: `Admin with ID '${id}' has been successfully deleted`,
    };
  }
}
