import {
  Entity,
  Column,
  OneToMany,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { RolePermission } from './role-permission.entity';
import { ModuleEntity } from './module.entity';
import { BaseEntity } from 'src/common/entities/base.entity';

export enum ActionType {
  CREATE = 'CREATE',
  READ = 'READ',
  UPDATE = 'UPDATE',
  DELETE = 'DELETE',
}

export enum PermissionModule {
  ADMIN = 'ADMIN',
  ADMIN_LIST = 'ADMIN_LIST',
  ADMIN_ROLE_PERMISSIONS = 'ADMIN_ROLE_PERMISSIONS',
  ADMIN_USER_LOGS = 'ADMIN_USER_LOGS',
  ADMIN_AUDIT_LOGS = 'ADMIN_AUDIT_LOGS',

  SETTING = 'SETTING',
  SETTING_SMTP = 'SETTING_SMTP',

  APPLICATION_USER = 'APPLICATION_USER',
  APPLICATION_USER_LIST = 'APPLICATION_USER_LIST',
}

@Entity('permissions')
@Index(['moduleId', 'action'], { unique: true })
export class Permission extends BaseEntity {
  @Column('uuid')
  moduleId: string;

  @ManyToOne(() => ModuleEntity, (module) => module.permissions, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'moduleId' })
  module: ModuleEntity;

  @Column({ name: 'action', type: 'varchar' })
  action: ActionType;

  @OneToMany(
    () => RolePermission,
    (rolePermission) => rolePermission.permission,
  )
  rolePermissions: RolePermission[];
}
