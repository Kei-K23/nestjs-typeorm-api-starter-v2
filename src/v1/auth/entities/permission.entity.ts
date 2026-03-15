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
  Relation,
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
  SETTING_BANNER = 'SETTING_BANNER',
  SETTING_ADS = 'SETTING_ADS',
  SETTING_SMTP = 'SETTING_SMTP',

  ANNOUNCEMENTS = 'ANNOUNCEMENTS',

  ACADEMIC = 'ACADEMIC',
  ACADEMIC_LEVELS = 'ACADEMIC_LEVELS',
  ACADEMIC_SUBJECTS = 'ACADEMIC_SUBJECTS',
  ACADEMIC_GRADES = 'ACADEMIC_GRADES',
  ACADEMIC_CHAPTERS = 'ACADEMIC_CHAPTERS',
  ACADEMIC_TUTORIALS = 'ACADEMIC_TUTORIALS',

  PACKAGE = 'PACKAGE',
  PACKAGE_LIST = 'PACKAGE_LIST',
  PACKAGE_USER_ACCESS = 'PACKAGE_USER_ACCESS',

  APPLICATION_USER = 'APPLICATION_USER',
  APPLICATION_USER_LIST = 'APPLICATION_USER_LIST',
  APPLICATION_SUBSCRIPTION_REPORT = 'APPLICATION_SUBSCRIPTION_REPORT',
  APPLICATION_BAN_USER = 'APPLICATION_BAN_USER',

  QUIZ_RESULT = 'QUIZ_RESULT',
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
  module: Relation<ModuleEntity>;

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
