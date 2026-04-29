import { randomUUID } from 'crypto';
import {
  BeforeInsert,
  CreateDateColumn,
  DeleteDateColumn,
  Index,
  PrimaryColumn,
  UpdateDateColumn,
} from 'typeorm';

export abstract class BaseEntity {
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

  @Index()
  @DeleteDateColumn()
  deletedAt?: Date;
}
