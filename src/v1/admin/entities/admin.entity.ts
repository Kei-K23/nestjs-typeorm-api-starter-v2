import { Exclude } from 'class-transformer';
import {
  Entity,
  Column,
  Index,
  ManyToOne,
  OneToMany,
  JoinColumn,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import { Role } from 'src/v1/auth/entities/role.entity';
import { RefreshToken } from 'src/v1/auth/entities/refresh-token.entity';
import { BaseEntity } from 'src/common/entities/base.entity';
import { hashPasswordIfNeeded } from 'src/common/utils/password-hash.util';

@Entity('admins')
export class Admin extends BaseEntity {
  @Index()
  @Column()
  fullName: string;

  @Column({ nullable: true })
  @Exclude()
  password: string;

  @Column({ unique: true })
  email: string;

  @Column({ nullable: true })
  profileImageUrl: string;

  @Column()
  roleId: string;

  @ManyToOne(() => Role, undefined, { onDelete: 'RESTRICT' })
  @JoinColumn({ name: 'roleId' })
  role: Role;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.admin)
  refreshTokens: RefreshToken[];

  @Index()
  @Column({ default: false })
  isBanned: boolean;

  @Column({ default: false })
  twoFactorEnabled: boolean;

  @Column({ type: 'timestamptz', nullable: true })
  lastLoginAt: Date;

  @Column({ type: 'timestamptz', nullable: true })
  lastLogoutAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    this.password = await hashPasswordIfNeeded(this.password);
  }
}
