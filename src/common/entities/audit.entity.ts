import { randomUUID } from 'crypto';
import {
  BeforeInsert,
  CreateDateColumn,
  PrimaryColumn,
  UpdateDateColumn,
} from 'typeorm';

export abstract class AuditEntity {
  @PrimaryColumn('uuid')
  id: string;

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = randomUUID();
    }
  }

  @CreateDateColumn({ type: 'timestamptz' })
  createdAt: Date;

  @UpdateDateColumn({ type: 'timestamptz' })
  updatedAt: Date;
}
