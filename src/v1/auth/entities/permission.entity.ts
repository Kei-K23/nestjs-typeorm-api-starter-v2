import {
  Entity,
  Column,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
  PrimaryColumn,
  BeforeInsert,
  DeleteDateColumn,
  Index,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { RolePermission } from './role-permission.entity';
import { v4 as uuidv4 } from 'uuid';
import { ModuleEntity } from './module.entity';

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

  REPORTING = 'REPORTING',
  REPORTING_APPLICATION_USER_REPORT = 'REPORTING_APPLICATION_USER_REPORT',
  REPORTING_TRANSACTION_REPORT = 'REPORTING_TRANSACTION_REPORT',

  SETTING = 'SETTING',
  SETTING_QUIZ = 'SETTING_QUIZ',
  SETTING_FAQ = 'SETTING_FAQ',
  SETTING_PNV = 'SETTING_PNV',
  SETTING_TNC = 'SETTING_TNC',
  SETTING_PRIVACY_POLICY = 'SETTING_PRIVACY_POLICY',
  SETTING_SMTP = 'SETTING_SMTP',

  ANNOUNCEMENTS = 'ANNOUNCEMENTS',

  PACKAGE = 'PACKAGE',
  PLAN_LIST = 'PLAN_LIST',
  PROMOTION_LIST = 'PROMOTION_LIST',
  GIFT_CODE_LIST = 'GIFT_CODE_LIST',

  APPLICATION_USER = 'APPLICATION_USER',
  APPLICATION_USER_LIST = 'APPLICATION_USER_LIST',
  APPLICATION_SUBSCRIPTION_REPORT = 'APPLICATION_SUBSCRIPTION_REPORT',
  APPLICATION_BAN_USER = 'APPLICATION_BAN_USER',

  QUIZ_RESULT = 'QUIZ_RESULT',

  CONTENT = 'CONTENT',
  CONTENT_CATEGORY = 'CONTENT_CATEGORY',
  CONTENT_SEASON = 'CONTENT_SEASON',
  CONTENT_EPISODE = 'CONTENT_EPISODE',
  CONTENT_CAST = 'CONTENT_CAST',
  CONTENT_CAST_ROLE = 'CONTENT_CAST_ROLE',
  CONTENT_GENRE = 'CONTENT_GENRE',
  CONTENT_LIST = 'CONTENT_LIST',
  CONTENT_COLLECTION = 'CONTENT_COLLECTION',

  CMS = 'CMS',
  CMS_BANNER = 'CMS_BANNER',
  CMS_ADS = 'CMS_ADS',
}

@Entity('permissions')
@Index(['moduleId', 'action'], { unique: true })
export class Permission {
  @PrimaryColumn('uuid')
  id: string;

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

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }

  @Index()
  @DeleteDateColumn()
  deletedAt?: Date;
}
