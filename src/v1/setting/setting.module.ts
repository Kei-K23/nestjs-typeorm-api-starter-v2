import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { SettingController } from './controllers/setting.controller';
import { FaqController } from './controllers/faq.controller';
import { BannerController } from './controllers/banner.controller';
import { SettingService } from './services/setting.service';
import { FaqService } from './services/faq.service';
import { BannerService } from './services/banner.service';
import { Setting } from './entities/setting.entity';
import { Faq } from './entities/faq.entity';
import { Banner } from './entities/banner.entity';
import { ActivityLogModule } from '../activity-log/activity-log.module';
import { SettingSeeder } from './seeders/setting.seeder';

@Module({
  imports: [
    TypeOrmModule.forFeature([Setting, Faq, Banner]),
    ActivityLogModule,
  ],
  controllers: [SettingController, FaqController, BannerController],
  providers: [SettingService, SettingSeeder, FaqService, BannerService],
  exports: [SettingService, FaqService, BannerService],
})
export class SettingModule {}
