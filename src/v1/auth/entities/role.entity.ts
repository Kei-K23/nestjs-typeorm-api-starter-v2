import { Entity, Column, OneToMany } from 'typeorm';
import { RolePermission } from './role-permission.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import { BaseEntity } from 'src/common/entities/base.entity';

@Entity('roles')
export class Role extends BaseEntity {
  @Column()
  name: string;

  @Column({ nullable: true })
  description: string;

  @OneToMany(() => Admin, (admin) => admin.role)
  admins: Admin[];

  @OneToMany(() => RolePermission, (rolePermission) => rolePermission.role)
  rolePermissions: RolePermission[];
}
