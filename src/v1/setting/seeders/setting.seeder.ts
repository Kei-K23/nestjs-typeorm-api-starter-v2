import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Setting } from '../entities/setting.entity';

@Injectable()
export class SettingSeeder {
  constructor(
    @InjectRepository(Setting)
    private settingRepository: Repository<Setting>,
  ) {}

  async seed() {
    const smtpSettings = [
      {
        key: 'smtp_host',
        value: 'smtp.gmail.com',
      },
      {
        key: 'smtp_port',
        value: '587',
      },
      {
        key: 'smtp_secure',
        value: 'false',
      },
      {
        key: 'smtp_username',
        value: 'arkar1712luffy@gmail.com',
      },
      {
        key: 'smtp_password',
        value: 'jjynxromygsfyxym',
      },
      {
        key: 'smtp_from_email',
        value: 'noreply@example.com',
      },
      {
        key: 'smtp_from_name',
        value: 'NestJS TypeORM API Starter',
      },
      {
        key: 'smtp_enabled',
        value: 'true',
      },
    ];

    for (const settingData of smtpSettings) {
      const existingSetting = await this.settingRepository.findOne({
        where: { key: settingData.key },
      });

      if (!existingSetting) {
        const setting = this.settingRepository.create(settingData);
        await this.settingRepository.save(setting);
        console.log(`Created SMTP setting: ${settingData.key}`);
      } else {
        console.log(`SMTP setting already exists: ${settingData.key}`);
      }
    }

    console.log('SMTP configuration seeding completed');
  }
}
