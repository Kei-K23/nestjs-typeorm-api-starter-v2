import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { User } from 'src/v1/user/entities/user.entity';
import { LogAction } from '../constants/log-action.enum';
import { LogStatus } from '../constants/log-status.enum';

@Entity('activity_logs')
@Index(['userId', 'action', 'createdAt'])
export class ActivityLog {
  // Integer PK intentional: high-volume append-only log table (avoids UUID overhead)
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  userId: string;

  @ManyToOne(() => User, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'userId' })
  user: User;

  @Column({ type: 'enum', enum: LogAction })
  action: LogAction;

  @Column({ type: 'text' })
  description: string;

  @Column({ nullable: true })
  resourceType: string;

  @Column({ nullable: true })
  resourceId: string;

  @Column({ nullable: true })
  ipAddress: string;

  @Column({ nullable: true })
  userAgent: string;

  @Column({ nullable: true })
  device: string;

  @Column({ nullable: true })
  browser: string;

  @Column({ nullable: true })
  os: string;

  @Column({ nullable: true })
  location: string;

  @Column({ type: 'enum', enum: LogStatus, default: LogStatus.SUCCESS })
  status: LogStatus;

  @Column({ type: 'json', nullable: true })
  metadata: Record<string, unknown>;

  @CreateDateColumn()
  createdAt: Date;
}
