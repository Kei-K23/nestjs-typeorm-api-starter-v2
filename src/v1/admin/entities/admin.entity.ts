import { Exclude } from 'class-transformer';
import {
  Entity,
  Column,
  BeforeUpdate,
  BeforeInsert,
  Index,
  ManyToOne,
  OneToMany,
  JoinColumn,
} from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { Role } from 'src/v1/auth/entities/role.entity';
import { RefreshToken } from 'src/v1/auth/entities/refresh-token.entity';
import { BaseEntity } from 'src/common/entities/base.entity';

@Entity('admins')
export class Admin extends BaseEntity {
  @Index()
  @Column()
  fullName: string;

  @Column({ nullable: true })
  @Exclude()
  password: string;

  @Index()
  @Column()
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

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    if (
      this.password &&
      !/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(this.password)
    ) {
      const rounds = Number(process.env.AUTH_PASSWORD_SALT_ROUNDS ?? 10);
      this.password = await bcrypt.hash(this.password, rounds);
    }
  }
}
