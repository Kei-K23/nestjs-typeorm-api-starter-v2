import { Entity, Column, ManyToOne, JoinColumn, Relation } from 'typeorm';
import { User } from 'src/v1/user/entities/user.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import { AuditEntity } from 'src/common/entities/audit.entity';

@Entity('refresh_tokens')
export class RefreshToken extends AuditEntity {
  @Column()
  token: string;

  @Column({ nullable: true })
  userId: string;

  @ManyToOne(() => User, (user) => user.refreshTokens, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'userId' })
  user: Relation<User>;

  @Column({ nullable: true })
  adminId: string;

  @ManyToOne(() => Admin, (admin) => admin.refreshTokens, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'adminId' })
  admin: Admin;

  @Column()
  expiresAt: Date;

  @Column({ default: false })
  isRevoked: boolean;
}
