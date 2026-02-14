import {
  Entity,
  Column,
  OneToMany,
  ManyToOne,
  JoinColumn,
  PrimaryColumn,
  CreateDateColumn,
  UpdateDateColumn,
  DeleteDateColumn,
  BeforeInsert,
  BeforeUpdate,
  Index,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import slugify from 'slugify';
import { Permission } from './permission.entity';

@Entity('modules')
export class ModuleEntity {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  name: string;

  @Column({ unique: true })
  code: string;

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

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Index()
  @DeleteDateColumn()
  deletedAt?: Date;

  @BeforeInsert()
  @BeforeUpdate()
  normalizeFields() {
    if (!this.id) {
      this.id = uuidv4();
    }

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
