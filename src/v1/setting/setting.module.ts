import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SettingController } from './controllers/setting.controller';
import { FaqController } from './controllers/faq.controller';
import { SettingService } from './services/setting.service';
import { FaqService } from './services/faq.service';
import { Setting } from './entities/setting.entity';
import { Faq } from './entities/faq.entity';
import { ActivityLogModule } from '../activity-log/activity-log.module';
import { SettingSeeder } from './seeders/setting.seeder';

@Module({
  imports: [TypeOrmModule.forFeature([Setting, Faq]), ActivityLogModule],
  controllers: [SettingController, FaqController],
  providers: [SettingService, SettingSeeder, FaqService],
  exports: [SettingService, FaqService],
})
export class SettingModule {}
