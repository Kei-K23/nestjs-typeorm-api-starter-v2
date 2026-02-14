import { Exclude } from 'class-transformer';
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  BeforeUpdate,
  BeforeInsert,
  PrimaryColumn,
  Index,
  DeleteDateColumn,
  ManyToOne,
  OneToMany,
  JoinColumn,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
import * as bcrypt from 'bcryptjs';
import { Role } from 'src/v1/auth/entities/role.entity';
import { RefreshToken } from 'src/v1/auth/entities/refresh-token.entity';

@Entity('admins')
export class Admin {
  @PrimaryColumn('uuid')
  id: string;

  @Index()
  @Column()
  fullName: string;

  @Column({ nullable: true })
  @Exclude()
  password: string;

  @Index()
  @Column()
  email: string;

  @Index()
  @Column()
  phone: string;

  @Column({ nullable: true })
  profileImageUrl: string;

  @Column({ nullable: true })
  dateOfBirth: string;

  @Column({ nullable: true })
  gender: string;

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

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Index()
  @DeleteDateColumn()
  deletedAt?: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }

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
