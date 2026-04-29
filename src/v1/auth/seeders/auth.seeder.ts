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
import { User, UserRegistrationStage } from 'src/v1/user/entities/user.entity';

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
  allowedActions?: ActionType[];
  children?: {
    name: string;
    code: PermissionModule;
    allowedActions?: ActionType[];
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
      {
        name: 'Admin',
        code: PermissionModule.ADMIN,
        children: [
          {
            name: 'Admin List',
            code: PermissionModule.ADMIN_LIST,
          },
          {
            name: 'Admin Role Permissions',
            code: PermissionModule.ADMIN_ROLE_PERMISSIONS,
          },
          {
            name: 'Admin User Logs',
            code: PermissionModule.ADMIN_USER_LOGS,
            allowedActions: [ActionType.READ],
          },
          {
            name: 'Admin Audit Logs',
            code: PermissionModule.ADMIN_AUDIT_LOGS,
            allowedActions: [ActionType.READ],
          },
        ],
      },
      {
        name: 'Setting',
        code: PermissionModule.SETTING,
        children: [
          {
            name: 'SMTP Setting',
            code: PermissionModule.SETTING_SMTP,
          },
        ],
      },
      {
        name: 'Application User',
        code: PermissionModule.APPLICATION_USER,
        children: [
          {
            name: 'Application User List',
            code: PermissionModule.APPLICATION_USER_LIST,
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
          ...(moduleSeed.allowedActions && {
            allowedActions: moduleSeed.allowedActions,
          }),
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
              ...(child.allowedActions && {
                allowedActions: child.allowedActions,
              }),
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
    const allowedActions = module.allowedActions?.length
      ? module.allowedActions
      : Object.values(ActionType);

    const permissions: Permission[] = [];
    for (const actionType of allowedActions) {
      const existing = await this.permissionRepository.findOne({
        where: { moduleId: module.id, action: actionType },
      });
      if (!existing) {
        const p = this.permissionRepository.create({
          moduleId: module.id,
          action: actionType,
        });
        permissions.push(await this.permissionRepository.save(p));
      } else {
        permissions.push(existing);
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
    const email = 'arkarmin@obs.com.mm';
    const existing = await this.adminRepository.findOne({ where: { email } });
    if (!existing) {
      await this.adminRepository.save(
        this.adminRepository.create({
          email,
          fullName: 'Super Admin',
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
          registrationStage: UserRegistrationStage.ACCOUNT_SETUP,
          password: 'passwordD123!@#',
        }),
      );
    }
  }
}
