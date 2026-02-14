import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_INTERCEPTOR } from '@nestjs/core';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UserModule } from './v1/user/user.module';
import { AuthModule } from './v1/auth/auth.module';
import { ActivityLogModule } from './v1/activity-log/activity-log.module';
import { ActivityLogInterceptor } from './v1/activity-log/interceptors/activity-log.interceptor';
import { SettingModule } from './v1/setting/setting.module';
import { CommonModule } from './common/common.module';
import dataSource from './data-source';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { AdminModule } from './v1/admin/admin.module';

@Module({
  imports: [
    CommonModule,
    ScheduleModule.forRoot(),
    ThrottlerModule.forRoot({
      throttlers: [
        {
          ttl: 60000,
          limit: 100,
        },
      ],
    }),
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    TypeOrmModule.forRoot({
      ...dataSource.options,
    }),
    AuthModule,
    UserModule,
    AdminModule,
    ActivityLogModule,
    SettingModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_INTERCEPTOR,
      useClass: ActivityLogInterceptor,
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})
export class AppModule {}
