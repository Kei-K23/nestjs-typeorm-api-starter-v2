import { Exclude } from 'class-transformer';
import { RefreshToken } from 'src/v1/auth/entities/refresh-token.entity';
import {
  Entity,
  Column,
  OneToMany,
  Index,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import { CacheKey } from 'src/v1/auth/entities/cache-key.entity';
import { BaseEntity } from 'src/common/entities/base.entity';
import { hashPasswordIfNeeded } from 'src/common/utils/password-hash.util';

export const LoginProvider = {
  SMS: 'SMS',
  GOOGLE: 'GOOGLE',
  APPLE: 'APPLE',
} as const;

export type LoginProvider = (typeof LoginProvider)[keyof typeof LoginProvider];

export const UserRegistrationStage = {
  OTP_VERIFY: 'OTP_VERIFY',
  PASSWORD_SETUP: 'PASSWORD_SETUP',
  ACCOUNT_SETUP: 'ACCOUNT_SETUP',
} as const;

export type UserRegistrationStage =
  (typeof UserRegistrationStage)[keyof typeof UserRegistrationStage];

@Entity('users')
export class User extends BaseEntity {
  @Index()
  @Column({ nullable: true })
  email: string;

  @Index()
  @Column({ nullable: true })
  fullName: string;

  @Column()
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

  @Column({ nullable: true })
  preferLanguage: string;

  @Column({
    type: 'enum',
    enum: UserRegistrationStage,
    default: UserRegistrationStage.OTP_VERIFY,
    nullable: true,
  })
  registrationStage: UserRegistrationStage;

  @Column({ type: 'varchar', nullable: true })
  fcmToken: string | null;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLogoutAt: Date;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => CacheKey, (cacheKey) => cacheKey.user)
  cacheKeys: CacheKey[];

  @Column({ type: 'varchar', nullable: true })
  googleId: string;

  @Column({ type: 'varchar', nullable: true })
  appleId: string;

  @Column({ type: 'varchar', nullable: true })
  loginProvider: LoginProvider;

  @BeforeInsert()
  @BeforeUpdate()
  async hashPassword() {
    this.password = await hashPasswordIfNeeded(this.password);
  }
}
