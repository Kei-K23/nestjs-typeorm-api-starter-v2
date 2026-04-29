import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { envValidationSchema } from '../common/config/env.validation';
import dataSource from '../data-source';
import { Admin } from '../v1/admin/entities/admin.entity';
import { ModuleEntity } from '../v1/auth/entities/module.entity';
import { Permission } from '../v1/auth/entities/permission.entity';
import { RolePermission } from '../v1/auth/entities/role-permission.entity';
import { Role } from '../v1/auth/entities/role.entity';
import { AuthSeeder } from '../v1/auth/seeders/auth.seeder';
import { Setting } from '../v1/setting/entities/setting.entity';
import { SettingSeeder } from '../v1/setting/seeders/setting.seeder';
import { User } from '../v1/user/entities/user.entity';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      validationSchema: envValidationSchema,
      validationOptions: {
        abortEarly: false,
      },
    }),
    TypeOrmModule.forRoot({
      ...dataSource.options,
    }),
    TypeOrmModule.forFeature([
      Admin,
      ModuleEntity,
      Permission,
      Role,
      RolePermission,
      Setting,
      User,
    ]),
  ],
  providers: [AuthSeeder, SettingSeeder],
})
export class SeederModule {}
