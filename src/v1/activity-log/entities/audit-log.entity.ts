import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  CreateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
} from 'typeorm';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import { LogAction } from '../constants/log-action.enum';
import { LogStatus } from '../constants/log-status.enum';

@Entity('audit_logs')
@Index(['adminId', 'action', 'createdAt'])
export class AuditLog {
  // Integer PK intentional: high-volume append-only log table (avoids UUID overhead)
  @PrimaryGeneratedColumn()
  id: number;

  // Nullable + SET NULL: audit history must survive admin account deletion
  @Column({ type: 'uuid', nullable: true })
  adminId: string | null;

  @ManyToOne(() => Admin, { nullable: true, onDelete: 'SET NULL' })
  @JoinColumn({ name: 'adminId' })
  admin: Admin;

  @Column({ type: 'enum', enum: LogAction })
  action: LogAction;

  @Column({ type: 'text' })
  description: string;

  @Column({ nullable: true })
  entityName: string;

  @Column({ nullable: true })
  entityId: string;

  @Column({ type: 'json', nullable: true })
  oldValue: Record<string, unknown>;

  @Column({ type: 'json', nullable: true })
  newValue: Record<string, unknown>;

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
