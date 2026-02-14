import { User } from 'src/v1/user/entities/user.entity';
import { Admin } from 'src/v1/admin/entities/admin.entity';
import {
  Entity,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  PrimaryColumn,
  BeforeInsert,
  BeforeUpdate,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

@Entity('refresh_tokens')
export class RefreshToken {
  @PrimaryColumn('uuid')
  id: string;

  @Column()
  token: string;

  @Column({ nullable: true })
  userId: string;

  @ManyToOne(() => User, (user) => user.refreshTokens, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'userId' })
  user: User;

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

  @CreateDateColumn()
  createdAt: Date;

  @BeforeInsert()
  @BeforeUpdate()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }
}
