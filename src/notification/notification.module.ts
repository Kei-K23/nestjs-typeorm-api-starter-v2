import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { NotificationService } from './notification.service';
import { EmailProcessor } from './processors/email.processor';
import { SmsProcessor } from './processors/sms.processor';
import {
  EMAIL_NOTIFICATION_QUEUE,
  SMS_NOTIFICATION_QUEUE,
} from './constants/notification.constants';

@Module({
  imports: [
    BullModule.registerQueue(
      { name: EMAIL_NOTIFICATION_QUEUE },
      { name: SMS_NOTIFICATION_QUEUE },
    ),
  ],
  providers: [NotificationService, EmailProcessor, SmsProcessor],
  exports: [NotificationService],
})
export class NotificationModule {}
