import { randomUUID } from 'crypto';
import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  BeforeInsert,
  PrimaryColumn,
  Relation,
} from 'typeorm';
import { User } from 'src/v1/user/entities/user.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';

export enum CacheKeyStatus {
  PENDING = 'pending',
  VERIFIED = 'verified',
  EXPIRED = 'expired',
  USED = 'used',
}

export enum CacheKeyService {
  TWO_FACTOR = 'two_factor',
  RESET_PASSWORD = 'reset_password',
}

@Entity('cache_keys')
export class CacheKey {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ nullable: true })
  userId: string | null;

  @ManyToOne(() => User, (user) => user.cacheKeys)
  @JoinColumn({ name: 'userId' })
  user: Relation<User>;

  @Column({ nullable: true })
  adminId: string | null;

  @ManyToOne(() => Admin, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'adminId' })
  admin: Admin;

  @Column({
    type: 'enum',
    enum: CacheKeyStatus,
    default: CacheKeyStatus.PENDING,
  })
  status: CacheKeyStatus;

  @Column({
    type: 'enum',
    enum: CacheKeyService,
  })
  service: CacheKeyService;

  @Column()
  code: string;

  @Column()
  expiresAt: Date;

  @Column({ type: 'varchar', nullable: true })
  requestId: string | null;

  @Column({ default: 0 })
  attempts: number;

  @Column({ default: 3 })
  maxAttempts: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = randomUUID();
    }
  }
}
