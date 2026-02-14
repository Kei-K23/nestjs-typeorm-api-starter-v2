import {
  BeforeInsert,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryColumn,
  UpdateDateColumn,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

@Entity('faqs')
export class Faq {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ type: 'varchar', nullable: false })
  question: string;

  @Column({ type: 'varchar', nullable: false })
  answer: string;

  @CreateDateColumn()
  createdAt: Date;

  @UpdateDateColumn()
  updatedAt: Date;

  @BeforeInsert()
  generateUUID() {
    if (!this.id) {
      this.id = uuidv4();
    }
  }
}
