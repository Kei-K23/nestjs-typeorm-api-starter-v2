import {
  Injectable,
  ConflictException,
  BadRequestException,
  Logger,
} from '@nestjs/common';
import { InjectDataSource, InjectRepository } from '@nestjs/typeorm';
import {
  Repository,
  DataSource,
  EntityManager,
  FindManyOptions,
} from 'typeorm';
import { Role } from '../entities/role.entity';
import { Permission } from '../entities/permission.entity';
import { RolePermission } from '../entities/role-permission.entity';
import { CreateRoleDto } from '../dto/create-role.dto';
import { UpdateRoleDto } from '../dto/update-role.dto';

@Injectable()
export class RoleService {
  private readonly logger = new Logger(RoleService.name);

  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    @InjectDataSource()
    private dataSource: DataSource,
  ) {}

  async findAll(page: number = 1, limit: number = 10, getAll: boolean = false) {
    const skip = (page - 1) * limit;
    const findOptions: FindManyOptions<Role> = {
      order: { createdAt: 'DESC' },
      relations: [
        'rolePermissions',
        'rolePermissions.permission',
        'rolePermissions.permission.module',
      ],
    };

    if (!getAll) {
      findOptions.skip = skip;
      findOptions.take = limit;
    }

    return await this.roleRepository.findAndCount(findOptions);
  }

  async findAllPermissions() {
    return this.permissionRepository.find({
      relations: ['module', 'module.parent', 'module.children'],
      order: { createdAt: 'DESC' },
    });
  }

  async findOne(id: string): Promise<Role | null> {
    return this.roleRepository.findOne({
      where: { id },
      relations: [
        'admins',
        'rolePermissions',
        'rolePermissions.permission',
        'rolePermissions.permission.module',
      ],
    });
  }

  async create(createRoleDto: CreateRoleDto): Promise<Role | null> {
    // Check if role with same name already exists
    const existingRole = await this.roleRepository.findOne({
      where: { name: createRoleDto.name },
    });

    if (existingRole) {
      this.logger.warn(`Role with name '${createRoleDto.name}' already exists`);
      throw new ConflictException(
        `Role with name '${createRoleDto.name}' already exists`,
      );
    }

    // Validate permission IDs
    await this.validatePermissionIds(createRoleDto.permissionIds);

    // Use transaction to ensure data consistency
    return await this.dataSource.transaction(async (manager) => {
      // Create the role
      const role = manager.create(Role, {
        name: createRoleDto.name,
        description: createRoleDto.description,
      });

      const savedRole = await manager.save(role);

      // Create role-permission relationships
      if (
        createRoleDto.permissionIds &&
        createRoleDto.permissionIds.length > 0
      ) {
        await this.assignPermissionsToRole(
          savedRole.id,
          createRoleDto.permissionIds,
          manager,
        );
      }

      // Return role with permissions
      this.logger.log(`Role created with ID: ${savedRole.id}`);
      return await manager.findOne(Role, {
        where: { id: savedRole.id },
        relations: [
          'rolePermissions',
          'rolePermissions.permission',
          'rolePermissions.permission.module',
        ],
      });
    });
  }

  async update(id: string, updateRoleDto: UpdateRoleDto): Promise<Role | null> {
    const role = await this.findOne(id);

    if (!role) {
      return null;
    }

    // Check if updating name and it conflicts with existing role
    if (updateRoleDto.name && updateRoleDto.name !== role.name) {
      const existingRole = await this.roleRepository.findOne({
        where: { name: updateRoleDto.name },
      });

      if (existingRole) {
        this.logger.warn(
          `Role with name '${updateRoleDto.name}' already exists`,
        );
        throw new ConflictException(
          `Role with name '${updateRoleDto.name}' already exists`,
        );
      }
    }

    // Validate permission IDs if provided
    if (updateRoleDto.permissionIds) {
      await this.validatePermissionIds(updateRoleDto.permissionIds);
    }

    // Use transaction to ensure data consistency
    return await this.dataSource.transaction(async (manager) => {
      // Update role basic info
      if (updateRoleDto.name || updateRoleDto.description) {
        await manager.update(Role, id, {
          name: updateRoleDto.name,
          description: updateRoleDto.description,
        });
      }

      // Update permissions if provided
      if (updateRoleDto.permissionIds !== undefined) {
        // Remove existing role-permission relationships
        await manager.delete(RolePermission, { roleId: id });

        // Add new role-permission relationships
        if (updateRoleDto.permissionIds.length > 0) {
          await this.assignPermissionsToRole(
            id,
            updateRoleDto.permissionIds,
            manager,
          );
        }
      }

      // Return updated role with permissions
      this.logger.log(`Role updated with ID: ${id}`);
      return await manager.findOne(Role, {
        where: { id },
        relations: [
          'rolePermissions',
          'rolePermissions.permission',
          'rolePermissions.permission.module',
        ],
      });
    });
  }

  async remove(id: string): Promise<boolean> {
    const role = await this.findOne(id);

    if (!role) {
      return false;
    }

    // Check if role has admins assigned
    if (role.admins && role.admins.length > 0) {
      this.logger.warn(
        `Cannot delete role with ID '${id}' that has admins assigned to it`,
      );
      throw new ConflictException(
        'Cannot delete role that has admins assigned to it',
      );
    }

    // Soft delete role
    await this.roleRepository.softDelete(id);
    this.logger.log(`Role with ID '${id}' has been successfully soft deleted`);
    return true;
  }

  private async validatePermissionIds(permissionIds: string[]): Promise<void> {
    if (!permissionIds || permissionIds.length === 0) {
      return;
    }

    const existingPermissions =
      await this.permissionRepository.findByIds(permissionIds);

    if (existingPermissions.length !== permissionIds.length) {
      const existingIds = existingPermissions.map((p) => p.id);
      const invalidIds = permissionIds.filter(
        (id) => !existingIds.includes(id),
      );
      this.logger.warn(`Invalid permission IDs: ${invalidIds.join(', ')}`);
      throw new BadRequestException(
        `Invalid permission IDs: ${invalidIds.join(', ')}`,
      );
    }
  }

  private async assignPermissionsToRole(
    roleId: string,
    permissionIds: string[],
    manager: EntityManager,
  ): Promise<void> {
    const rolePermissions = permissionIds.map((permissionId) =>
      manager.create(RolePermission, {
        roleId,
        permissionId,
      }),
    );

    await manager.save(RolePermission, rolePermissions);
  }
}
