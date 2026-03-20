import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { EmailServiceUtils } from 'src/common/utils/email-service.utils';
import {
  EMAIL_NOTIFICATION_QUEUE,
  EmailJobName,
} from '../constants/notification.constants';
import {
  SendForgotPasswordResetCodePayload,
  SendTwoFactorCodePayload,
} from '../interfaces/notification-jobs.interface';

@Processor(EMAIL_NOTIFICATION_QUEUE)
export class EmailProcessor extends WorkerHost {
  private readonly logger = new Logger(EmailProcessor.name);

  constructor(private readonly emailServiceUtils: EmailServiceUtils) {
    super();
  }

  async process(job: Job): Promise<void> {
    this.logger.log(`Processing email job: ${job.name} (id: ${job.id})`);

    switch (job.name as EmailJobName) {
      case EmailJobName.SEND_TWO_FACTOR_CODE:
        await this.emailServiceUtils.sendTwoFactorCode(
          job.data as SendTwoFactorCodePayload,
        );
        break;

      case EmailJobName.SEND_FORGOT_PASSWORD_RESET_CODE:
        await this.emailServiceUtils.sendForgotPasswordResetCode(
          job.data as SendForgotPasswordResetCodePayload,
        );
        break;

      default:
        this.logger.warn(`Unknown email job: ${job.name}`);
    }
  }
}
