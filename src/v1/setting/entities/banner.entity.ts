import {
  BeforeInsert,
  Column,
  CreateDateColumn,
  Entity,
  PrimaryColumn,
  UpdateDateColumn,
} from 'typeorm';
import { v4 as uuidv4 } from 'uuid';

@Entity('banners')
export class Banner {
  @PrimaryColumn('uuid')
  id: string;

  @Column({ type: 'varchar', nullable: false })
  imageUrl: string;

  @Column({ type: 'int', nullable: false })
  orderIndex: number;

  @Column({ type: 'varchar', nullable: false })
  type: string;

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
