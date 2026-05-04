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

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;
}
