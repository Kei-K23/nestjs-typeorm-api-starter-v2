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

export const LoginProvider = {
  SMS: 'sms',
  GOOGLE: 'google',
  APPLE: 'apple',
} as const;

export type LoginProvider = (typeof LoginProvider)[keyof typeof LoginProvider];

export const UserRegistrationStage = {
  OTP_VERIFY: 'otpVerify',
  PASSWORD_SETUP: 'passwordSetup',
  ACCOUNT_SETUP: 'accountSetup',
} as const;

// This creates a union type of the *values*
export type UserRegistrationStage =
  (typeof UserRegistrationStage)[keyof typeof UserRegistrationStage];

@Entity('users')
export class User {
  @PrimaryColumn('uuid')
  id: string;

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
  @Column({ default: false, nullable: true })
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

  @Column({ nullable: true, default: '' })
  fcmToken: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @Column({ type: 'timestamp', nullable: true })
  lastLoginAt: Date;

  @OneToMany(() => RefreshToken, (refreshToken) => refreshToken.user)
  refreshTokens: RefreshToken[];

  @OneToMany(() => CacheKey, (cacheKey) => cacheKey.user)
  cacheKeys: CacheKey[];

  @Index()
  @DeleteDateColumn()
  deletedAt?: Date;

  @Column({ type: 'varchar', nullable: true })
  googleId: string;

  @Column({ type: 'varchar', nullable: true })
  appleId: string;

  @Column({ type: 'varchar', nullable: true })
  loginProvider: LoginProvider;

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
