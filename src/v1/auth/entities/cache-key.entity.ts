import {
  Entity,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  BeforeInsert,
  BeforeUpdate,
  PrimaryColumn,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';
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
  user: User;

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

  @Column({ default: 0 })
  attempts: number;

  @Column({ default: 3 })
  maxAttempts: number;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }
}
