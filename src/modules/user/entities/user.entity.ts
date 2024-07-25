import { IsEmail, IsString } from 'class-validator';
import { BaseEntity } from 'src/common/entities/base.entity';
import { Column, Entity } from 'typeorm';

@Entity('users')
export class UserEntity extends BaseEntity {
  @Column({ type: 'varchar', length: 100 })
  @IsEmail()
  @IsString()
  email: string;

  @Column({ type: 'varchar', length: 225 })
  @IsString()
  password: string;
}
