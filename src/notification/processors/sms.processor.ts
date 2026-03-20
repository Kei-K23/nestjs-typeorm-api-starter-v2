import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { SMSPhoServiceUtils } from 'src/common/utils/sms-pho-service.utils';
import {
  SMS_NOTIFICATION_QUEUE,
  SmsJobName,
} from '../constants/notification.constants';
import {
  SendOtpPayload,
  VerifyOtpPayload,
} from '../interfaces/notification-jobs.interface';

@Processor(SMS_NOTIFICATION_QUEUE)
export class SmsProcessor extends WorkerHost {
  private readonly logger = new Logger(SmsProcessor.name);

  constructor(private readonly smsPhoServiceUtils: SMSPhoServiceUtils) {
    super();
  }

  async process(job: Job): Promise<any> {
    this.logger.log(`Processing SMS job: ${job.name} (id: ${job.id})`);

    switch (job.name as SmsJobName) {
      case SmsJobName.SEND_OTP:
        return this.smsPhoServiceUtils.sendOTP(job.data as SendOtpPayload);

      case SmsJobName.VERIFY_OTP:
        return this.smsPhoServiceUtils.verifyOTP(job.data as VerifyOtpPayload);

      default:
        this.logger.warn(`Unknown SMS job: ${job.name}`);
    }
  }
}
