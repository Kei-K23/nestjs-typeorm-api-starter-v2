import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Role } from '../entities/role.entity';
import {
  Permission,
  PermissionModule,
  ActionType,
} from '../entities/permission.entity';
import { RolePermission } from '../entities/role-permission.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import { ModuleEntity } from '../entities/module.entity';
import { User, UserType } from 'src/v1/user/entities/user.entity';

interface RoleConfig {
  name: string;
  description: string;
  modules: {
    [module: string]: ActionType[];
  };
}

interface ModuleSeed {
  name: string;
  code: PermissionModule;
  children?: {
    name: string;
    code: PermissionModule;
  }[];
}

@Injectable()
export class AuthSeeder {
  constructor(
    @InjectRepository(Role)
    private roleRepository: Repository<Role>,
    @InjectRepository(Permission)
    private permissionRepository: Repository<Permission>,
    @InjectRepository(RolePermission)
    private rolePermissionRepository: Repository<RolePermission>,
    @InjectRepository(Admin)
    private adminRepository: Repository<Admin>,
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(ModuleEntity)
    private moduleRepository: Repository<ModuleEntity>,
  ) {}

  private getRoleConfigurations(allModules: string[]): RoleConfig[] {
    const allPermissions = Object.values(ActionType).filter(
      (value) => typeof value === 'string',
    ) as ActionType[];

    const moduleAccess = Object.fromEntries(
      allModules.map((module) => [module, allPermissions]),
    );
    return [
      {
        name: 'Super Admin',
        description: 'Super Administrator role with full access',
        modules: moduleAccess,
      },
    ];
  }

  async seed() {
    const modulesToSeed: ModuleSeed[] = [
      { name: 'Users', code: PermissionModule.USERS },
      { name: 'Admins', code: PermissionModule.ADMINS },
      { name: 'Roles', code: PermissionModule.ROLES },
      { name: 'Activity Logs', code: PermissionModule.ACTIVITY_LOGS },
      {
        name: 'Settings',
        code: PermissionModule.SETTINGS,
        children: [
          {
            name: 'SMTP Settings',
            code: PermissionModule.SMTP_SETTINGS,
          },
          {
            name: 'TNC Settings',
            code: PermissionModule.TNC_SETTINGS,
          },
        ],
      },
      {
        name: 'Package',
        code: PermissionModule.PACKAGES,
        children: [
          {
            name: 'Package Plan',
            code: PermissionModule.PACKAGE_PLAN,
          },
          {
            name: 'Package Scholarship',
            code: PermissionModule.PACKAGE_SCHOLARSHIP,
          },
        ],
      },
      {
        name: 'Academic',
        code: PermissionModule.ACADEMIC,
        children: [
          { name: 'Academic Levels', code: PermissionModule.ACADEMIC_LEVELS },
          {
            name: 'Academic Subjects',
            code: PermissionModule.ACADEMIC_SUBJECTS,
          },
          { name: 'Academic Grades', code: PermissionModule.ACADEMIC_GRADES },
          {
            name: 'Academic Chapters',
            code: PermissionModule.ACADEMIC_CHAPTERS,
          },
          {
            name: 'Academic Tutorials',
            code: PermissionModule.ACADEMIC_TUTORIALS,
          },
        ],
      },
    ];

    const createdModules: ModuleEntity[] = [];

    for (const moduleSeed of modulesToSeed) {
      let moduleEntity = await this.moduleRepository.findOne({
        where: { code: moduleSeed.code },
      });

      if (!moduleEntity) {
        moduleEntity = this.moduleRepository.create({
          name: moduleSeed.name,
          code: moduleSeed.code,
        });
        moduleEntity = await this.moduleRepository.save(moduleEntity);
      }

      if (moduleSeed.children && moduleSeed.children.length > 0) {
        for (const child of moduleSeed.children) {
          let childModule = await this.moduleRepository.findOne({
            where: { code: child.code, parentId: moduleEntity.id },
          });

          if (!childModule) {
            childModule = this.moduleRepository.create({
              name: child.name,
              code: child.code,
              parentId: moduleEntity.id,
            });
            childModule = await this.moduleRepository.save(childModule);
          }

          createdModules.push(childModule);
        }
      }

      createdModules.push(moduleEntity);
    }

    const moduleCodes = createdModules.map((m) => m.code);

    const roleConfigs = this.getRoleConfigurations(moduleCodes);
    const createdRoles: Role[] = [];

    const modulePermissions: { [moduleCode: string]: Permission[] } = {};
    for (const moduleEntity of createdModules) {
      modulePermissions[moduleEntity.code] =
        await this.createModulePermissions(moduleEntity);
    }

    // Create roles and assign permissions dynamically
    for (const roleConfig of roleConfigs) {
      const role = await this.createRole(
        roleConfig.name,
        roleConfig.description,
      );
      createdRoles.push(role);

      await this.assignPermissionsToRoleFromConfig(
        role,
        roleConfig.modules,
        modulePermissions,
      );
    }

    // Super Admin user
    const superAdminRole = createdRoles.find((r) => r.name === 'Super Admin');
    await this.createSuperAdmin(superAdminRole!);

    // Normal user
    await this.createNormalUser();
  }

  private async createRole(name: string, description: string): Promise<Role> {
    const existingRole = await this.roleRepository.findOne({ where: { name } });
    if (existingRole) return existingRole;
    return this.roleRepository.save(
      this.roleRepository.create({ name, description }),
    );
  }

  private async createModulePermissions(
    module: ModuleEntity,
  ): Promise<Permission[]> {
    const permissions: Permission[] = [];
    for (const actionType of Object.values(ActionType)) {
      if (typeof actionType === 'string') {
        const existing = await this.permissionRepository.findOne({
          where: { moduleId: module.id, action: actionType },
        });
        if (!existing) {
          const p = this.permissionRepository.create({
            moduleId: module.id,
            action: actionType as ActionType,
          });
          permissions.push(await this.permissionRepository.save(p));
        } else {
          permissions.push(existing);
        }
      }
    }
    return permissions;
  }

  private async assignPermissionsToRoleFromConfig(
    role: Role,
    moduleConfig: { [module: string]: ActionType[] },
    modulePermissions: { [module: string]: Permission[] },
  ) {
    for (const [module, allowed] of Object.entries(moduleConfig)) {
      const permissions = modulePermissions[module] || [];
      const filtered = permissions.filter((p) => allowed.includes(p.action));
      await this.assignPermissionsToRole(role, filtered);
    }
  }

  private async assignPermissionsToRole(role: Role, permissions: Permission[]) {
    for (const permission of permissions) {
      const exists = await this.rolePermissionRepository.findOne({
        where: { roleId: role.id, permissionId: permission.id },
      });
      if (!exists) {
        await this.rolePermissionRepository.save(
          this.rolePermissionRepository.create({
            roleId: role.id,
            permissionId: permission.id,
          }),
        );
      }
    }
  }

  private async createSuperAdmin(role: Role): Promise<void> {
    const email = 'arkarmin@gmail.com';
    const existing = await this.adminRepository.findOne({ where: { email } });
    if (!existing) {
      await this.adminRepository.save(
        this.adminRepository.create({
          email,
          fullName: 'Super Admin',
          phone: '09756192218',
          roleId: role.id,
          password: 'passwordD123!@#',
        }),
      );
    }
  }

  private async createNormalUser(): Promise<void> {
    const email = 'suthinzar@obs.com.mm';
    const existing = await this.userRepository.findOne({ where: { email } });
    if (!existing) {
      await this.userRepository.save(
        this.userRepository.create({
          email,
          fullName: 'Suthinzar',
          phone: '095085730',
          userType: UserType.Student,
          division: 'Yangon',
          city: 'Yangon',
          password: 'passwordD123!@#',
        }),
      );
    }
  }
}
