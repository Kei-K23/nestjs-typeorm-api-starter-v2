import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserActivityLog } from './entities/user-activity-log.entity';
import { ActivityLogService } from './services/activity-log.service';
import { ActivityLogController } from './controllers/activity-log.controller';
import { ActivityLogInterceptor } from './interceptors/activity-log.interceptor';

@Module({
  imports: [TypeOrmModule.forFeature([UserActivityLog])],
  controllers: [ActivityLogController],
  providers: [ActivityLogService, ActivityLogInterceptor],
  exports: [ActivityLogService, ActivityLogInterceptor],
})
export class ActivityLogModule {}
