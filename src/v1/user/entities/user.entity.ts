import { Exclude } from 'class-transformer';
import { RefreshToken } from 'src/v1/auth/entities/refresh-token.entity';
import { v4 as uuidv4 } from 'uuid';
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  OneToMany,
  BeforeUpdate,
  BeforeInsert,
  PrimaryColumn,
  Index,
  DeleteDateColumn,
} from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { CacheKey } from 'src/v1/auth/entities/cache-key.entity';
import { Announcement } from 'src/v1/announcement/entities/announcement.entity';

export const UserType = {
  Student: 'student',
  Teacher: 'teacher',
  Parent: 'parent',
} as const;

// This creates a union type of the *values*
export type UserType = (typeof UserType)[keyof typeof UserType];

@Entity('users')
export class User {
  @PrimaryColumn('uuid')
  id: string;

  @Index()
  @Column({ nullable: true })
  email: string;

  @Index()
  @Column()
  fullName: string;

  @Column({ unique: true })
  phone: string;

  @Column({ nullable: true })
  @Exclude()
  password: string;

  @Index()
  @Column({ default: false })
  isBanned: boolean;

  @Column({ nullable: true })
  profileImageUrl: string;

  @Column({ nullable: true })
  dateOfBirth: string;

  @Column({ nullable: true })
  gender: string;

  @Index()
  @Column()
  userType: UserType;

  @Column({ nullable: true })
  preferLanguage: string;

  @Column()
  division: string;

  @Column()
  city: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => Announcement, (announcement) => announcement.toUser)
  announcements: Announcement[];

  @OneToMany(() => CacheKey, (cacheKey) => cacheKey.user)
  cacheKeys: CacheKey[];

  @Index()
  @DeleteDateColumn()
  deletedAt?: Date;

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
