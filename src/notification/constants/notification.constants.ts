export const EMAIL_NOTIFICATION_QUEUE = 'email-notification';
export const SMS_NOTIFICATION_QUEUE = 'sms-notification';

export enum EmailJobName {
  SEND_TWO_FACTOR_CODE = 'send_two_factor_code',
  SEND_FORGOT_PASSWORD_RESET_CODE = 'send_forgot_password_reset_code',
}

export enum SmsJobName {
  SEND_OTP = 'send_otp',
  VERIFY_OTP = 'verify_otp',
}
