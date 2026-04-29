import { Entity, Column } from 'typeorm';
import { BaseEntity } from 'src/common/entities/base.entity';

@Entity('settings')
export class Setting extends BaseEntity {
  @Column({ nullable: false, unique: true })
  key: string;

  @Column({ nullable: true, default: '' })
  value: string;
}
