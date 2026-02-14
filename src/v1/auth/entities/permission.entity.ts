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
  USERS = 'USERS',
  ADMINS = 'ADMINS',
  ROLES = 'ROLES',
  ACTIVITY_LOGS = 'ACTIVITY_LOGS',
  SETTINGS = 'SETTINGS',
  SMTP_SETTINGS = 'SMTP_SETTINGS',
  TNC_SETTINGS = 'TNC_SETTINGS',
  ACADEMIC = 'ACADEMIC',
  ACADEMIC_LEVELS = 'ACADEMIC_LEVELS',
  ACADEMIC_SUBJECTS = 'ACADEMIC_SUBJECTS',
  ACADEMIC_GRADES = 'ACADEMIC_GRADES',
  ACADEMIC_CHAPTERS = 'ACADEMIC_CHAPTERS',
  ACADEMIC_TUTORIALS = 'ACADEMIC_TUTORIALS',
  PACKAGES = 'PACKAGES',
  PACKAGE_PLAN = 'PACKAGE_PLAN',
  PACKAGE_SCHOLARSHIP = 'PACKAGE_SCHOLARSHIP',
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
