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
          },
          {
            name: 'Admin Audit Logs',
            code: PermissionModule.ADMIN_AUDIT_LOGS,
          },
        ],
      },
      {
        name: 'Reporting',
        code: PermissionModule.REPORTING,
        children: [
          {
            name: 'Application User Report',
            code: PermissionModule.REPORTING_APPLICATION_USER_REPORT,
          },
          {
            name: 'Transaction Report',
            code: PermissionModule.REPORTING_TRANSACTION_REPORT,
          },
        ],
      },
      {
        name: 'Setting',
        code: PermissionModule.SETTING,
        children: [
          {
            name: 'Quiz Setting',
            code: PermissionModule.SETTING_QUIZ,
          },
          {
            name: 'FAQ Setting',
            code: PermissionModule.SETTING_FAQ,
          },
          {
            name: 'PNV Setting',
            code: PermissionModule.SETTING_PNV,
          },
          {
            name: 'TNC Setting',
            code: PermissionModule.SETTING_TNC,
          },
          {
            name: 'Banner Setting',
            code: PermissionModule.SETTING_BANNER,
          },
          {
            name: 'Ads Setting',
            code: PermissionModule.SETTING_ADS,
          },
          {
            name: 'SMTP Setting',
            code: PermissionModule.SETTING_SMTP,
          },
        ],
      },
      {
        name: 'Announcements',
        code: PermissionModule.ANNOUNCEMENTS,
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
      {
        name: 'Package',
        code: PermissionModule.PACKAGE,
        children: [
          {
            name: 'Package List',
            code: PermissionModule.PACKAGE_LIST,
          },
          {
            name: 'Package User Access',
            code: PermissionModule.PACKAGE_USER_ACCESS,
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
          {
            name: 'Application Subscription Report',
            code: PermissionModule.APPLICATION_SUBSCRIPTION_REPORT,
          },
          {
            name: 'Application Ban User',
            code: PermissionModule.APPLICATION_BAN_USER,
          },
        ],
      },
      {
        name: 'Quiz Result',
        code: PermissionModule.QUIZ_RESULT,
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
