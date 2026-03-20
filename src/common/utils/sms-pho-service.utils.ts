import {
  Injectable,
  BadRequestException,
  InternalServerErrorException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios';

@Injectable()
export class SMSPhoServiceUtils {
  private readonly apiBase: string;
  private readonly accessToken: string;
  private readonly brand: string;
  private readonly fromName: string;
  private readonly enabled: boolean;

  constructor(private readonly config: ConfigService) {
    const key = this.config.get<string>('SMS_POH_API_KEY');
    const secret = this.config.get<string>('SMS_POH_API_SECRET_KEY');
    this.apiBase = this.config.get<string>('SMS_POH_BASE_API_URL') || '';
    this.brand = this.config.get<string>('SMS_POH_API_BRAND') || 'SMSPoh';
    this.fromName =
      this.config.get<string>('SMS_POH_API_SENDER_ID') || this.brand;

    if (!key || !secret || !this.apiBase) {
      const env = this.config.get<string>('NODE_ENV') || 'development';
      if (env === 'development' || env === 'test') {
        this.enabled = false;
        this.accessToken = '';
        return;
      }
      throw new InternalServerErrorException(
        'SMS provider configuration missing',
      );
    }
    this.enabled = true;
    this.accessToken = Buffer.from(`${key}:${secret}`).toString('base64');
  }

  async sendOTP(params: {
    to: string;
    message: string;
    ttl?: number;
    pinLength?: number;
    brand?: string;
    from?: string;
  }): Promise<{
    success: boolean;
    requestId: string;
  }> {
    if (!this.enabled) {
      throw new InternalServerErrorException('SMS provider is not configured');
    }
    const { to, message } = params;
    const ttl = params.ttl ?? 300;
    const pinLength = params.pinLength ?? 6;
    const fromName = encodeURIComponent(this.fromName);
    const brand = encodeURIComponent(this.brand);
    const encodedTo = encodeURIComponent(to);
    const encodedMessage = encodeURIComponent(message);

    const url = `${this.apiBase}/otp/request?accessToken=${this.accessToken}&from=${fromName}&to=${encodedTo}&brand=${brand}&ttl=${ttl}&pinLength=${pinLength}&template=${encodedMessage}`;

    try {
      const res = await axios.post(url, {});
      const data = res.data;
      if (!data?.requestId) {
        throw new InternalServerErrorException('Invalid SMS provider response');
      }
      return { success: true, requestId: data.requestId };
    } catch (e: any) {
      const text = e?.response?.data;
      throw new InternalServerErrorException(
        typeof text === 'string' ? text : 'Error when sending SMS',
      );
    }
  }

  async verifyOTP(params: { requestId: string; code: string }) {
    if (!this.enabled) {
      throw new InternalServerErrorException('SMS provider is not configured');
    }
    const { requestId, code } = params;
    const encodedCode = encodeURIComponent(code);
    const url = `${this.apiBase}/otp/verify?requestId=${requestId}&code=${encodedCode}&accessToken=${this.accessToken}`;

    try {
      const res = await axios.post(url, {});
      const data = res.data;
      if (!data?.verifiedAt) {
        throw new BadRequestException('Invalid OTP or request ID');
      }
      return { success: true, verifiedAt: data.verifiedAt, to: data.to };
    } catch (e: any) {
      const text = e?.response?.data;
      throw new BadRequestException(
        typeof text === 'string' ? text : 'Invalid OTP or request ID',
      );
    }
  }
}
