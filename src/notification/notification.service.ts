import { Injectable, Logger, OnModuleDestroy } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { ConfigService } from '@nestjs/config';
import { Queue, QueueEvents } from 'bullmq';
import {
  EMAIL_NOTIFICATION_QUEUE,
  EmailJobName,
  SMS_NOTIFICATION_QUEUE,
  SmsJobName,
} from './constants/notification.constants';
import {
  SendForgotPasswordResetCodePayload,
  SendOtpPayload,
  SendTwoFactorCodePayload,
  VerifyOtpPayload,
} from './interfaces/notification-jobs.interface';

@Injectable()
export class NotificationService implements OnModuleDestroy {
  private readonly logger = new Logger(NotificationService.name);
  private readonly emailQueueEvents: QueueEvents;
  private readonly smsQueueEvents: QueueEvents;

  constructor(
    @InjectQueue(EMAIL_NOTIFICATION_QUEUE) private readonly emailQueue: Queue,
    @InjectQueue(SMS_NOTIFICATION_QUEUE) private readonly smsQueue: Queue,
    private readonly configService: ConfigService,
  ) {
    const connection = {
      host: this.configService.get('REDIS_HOST', 'localhost'),
      port: this.configService.get<number>('REDIS_PORT', 6379),
    };
    this.emailQueueEvents = new QueueEvents(EMAIL_NOTIFICATION_QUEUE, {
      connection,
    });
    this.smsQueueEvents = new QueueEvents(SMS_NOTIFICATION_QUEUE, {
      connection,
    });
  }

  async onModuleDestroy() {
    await this.emailQueueEvents.close();
    await this.smsQueueEvents.close();
  }

  // ─── Email (fire-and-forget) ───────────────────────────────────────────────

  async sendTwoFactorCode(payload: SendTwoFactorCodePayload): Promise<void> {
    await this.emailQueue.add(EmailJobName.SEND_TWO_FACTOR_CODE, payload, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 2000 },
    });
    this.logger.log(`Queued 2FA email for ${payload.email}`);
  }

  async sendForgotPasswordResetCode(
    payload: SendForgotPasswordResetCodePayload,
  ): Promise<void> {
    await this.emailQueue.add(
      EmailJobName.SEND_FORGOT_PASSWORD_RESET_CODE,
      payload,
      {
        attempts: 3,
        backoff: { type: 'exponential', delay: 2000 },
      },
    );
    this.logger.log(`Queued password reset email for ${payload.email}`);
  }

  // ─── SMS (wait for result — requestId / verification needed by caller) ─────

  async sendSmsOtp(
    payload: SendOtpPayload,
  ): Promise<{ success: boolean; requestId: string }> {
    const job = await this.smsQueue.add(SmsJobName.SEND_OTP, payload, {
      attempts: 3,
      backoff: { type: 'exponential', delay: 1000 },
    });
    this.logger.log(`Queued SMS OTP for ${payload.to}`);
    return (await job.waitUntilFinished(this.smsQueueEvents)) as {
      success: boolean;
      requestId: string;
    };
  }

  async verifySmsOtp(
    payload: VerifyOtpPayload,
  ): Promise<{ success: boolean; verifiedAt: string; to: string }> {
    const job = await this.smsQueue.add(SmsJobName.VERIFY_OTP, payload, {
      attempts: 1,
    });
    this.logger.log(
      `Queued SMS OTP verification for requestId ${payload.requestId}`,
    );
    return (await job.waitUntilFinished(this.smsQueueEvents)) as {
      success: boolean;
      verifiedAt: string;
      to: string;
    };
  }
}
