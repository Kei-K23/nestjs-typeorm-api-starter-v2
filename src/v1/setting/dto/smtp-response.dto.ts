import { Expose } from 'class-transformer';

export class SMTPResponseDto {
  @Expose()
  smtpHost: string;

  @Expose()
  smtpPort: number;

  @Expose()
  smtpSecure: boolean;

  @Expose()
  smtpUsername: string;

  @Expose()
  smtpPassword: string;

  @Expose()
  smtpFromEmail: string;

  @Expose()
  smtpFromName: string;

  @Expose()
  smtpEnabled: boolean;

  @Expose()
  createdAt: Date;

  @Expose()
  updatedAt: Date;
}
