import {
  Entity,
  Column,
  OneToMany,
  ManyToOne,
  JoinColumn,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import slugify from 'slugify';
import { ActionType, Permission } from './permission.entity';
import { BaseEntity } from 'src/common/entities/base.entity';

@Entity('modules')
export class ModuleEntity extends BaseEntity {
  @Column()
  name: string;

  @Column({ unique: true })
  code: string;

  @Column({ type: 'simple-array', default: 'CREATE,READ,UPDATE,DELETE' })
  allowedActions: ActionType[];

  @Column({ type: 'uuid', nullable: true })
  parentId?: string;

  @ManyToOne(() => ModuleEntity, (module) => module.children, {
    onDelete: 'SET NULL',
  })
  @JoinColumn({ name: 'parentId' })
  parent?: ModuleEntity;

  @OneToMany(() => ModuleEntity, (module) => module.parent)
  children: ModuleEntity[];

  @OneToMany(() => Permission, (permission) => permission.module)
  permissions: Permission[];

  @BeforeInsert()
  @BeforeUpdate()
  normalizeCode() {
    if (this.name && !this.code) {
      this.code = slugify(this.name, {
        lower: true,
        strict: true,
        replacement: '_',
        trim: true,
      }).toUpperCase();
    }
  }
}
