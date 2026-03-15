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
  private readonly isProduction: boolean;

  constructor(private readonly config: ConfigService) {
    const key = this.config.get<string>('SMS_POH_API_KEY');
    const secret = this.config.get<string>('SMS_POH_API_SECRET_KEY');
    this.apiBase = this.config.get<string>('SMS_POH_BASE_API_URL') || '';
    this.brand = this.config.get<string>('SMS_POH_API_BRAND') || 'SMSPoh';
    this.fromName =
      this.config.get<string>('SMS_POH_API_SENDER_ID') || this.brand;
    this.isProduction =
      this.config.get<string>('SMS_POH_API_PRODUCTION') === 'production';

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
    const brand = encodeURIComponent(this.brand);
    const encodedTo = encodeURIComponent(to);
    const encodedMessage = encodeURIComponent(message);
    const forAtomMobileUser = encodeURIComponent('SMSPohTest');
    const forMPTAndOordeooUser = encodeURIComponent('SMSPoh Demo');
    const operatorName = this.getMobileOperator({
      phone: to,
    });

    const fromSender =
      operatorName === 'Telenor' ? forAtomMobileUser : forMPTAndOordeooUser;

    const fromName = this.isProduction ? this.fromName : fromSender;

    const url = `${this.apiBase}/otp/request?accessToken=${this.accessToken}&from=${fromName}&to=${encodedTo}&brand=${brand}&ttl=${ttl}&pinLength=${pinLength}&template=${encodedMessage}`;

    try {
      const res = await axios.post(url, {});
      const data = res.data;

      const requestId = data?.requestId;

      if (!requestId) {
        throw new InternalServerErrorException(
          `Invalid SMS provider response: ${JSON.stringify(data)}`,
        );
      }
      return { success: true, requestId };
    } catch (e: any) {
      if (e instanceof InternalServerErrorException) {
        throw e;
      }
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

  private getMobileOperator({ phone }) {
    // Normalize phone number: remove spaces, dashes, etc.
    const normalized: string = phone.replace(/[^0-9]/g, '');

    let local = normalized;

    // Handle international format 959...
    if (normalized.startsWith('959')) {
      local = '0' + normalized.slice(2);
    } else if (
      normalized.startsWith('9') &&
      normalized.length >= 8 &&
      !normalized.startsWith('95')
    ) {
      // Handle case where it might be 9xxxxxxxxx (missing 0 and 95) - unlikely but possible
      local = '0' + normalized;
    }

    // Ensure starts with "09" for local format check
    if (!local.startsWith('09')) {
      // If it is just 9xxxxxxxxx, make it 09xxxxxxxxx
      if (local.startsWith('9')) {
        local = '0' + local;
      }
    }

    // Final sanity check for local format
    if (!local.startsWith('09')) {
      return 'Invalid number';
    }

    // Match by prefixes
    if (/^097\d{7,8}$/.test(local)) {
      return 'Telenor';
    } else if (/^098\d{7,8}$/.test(local) || /^099\d{7,8}$/.test(local)) {
      return 'Ooredoo';
    } else if (/^096\d{7,8}$/.test(local)) {
      return 'Mytel';
    } else if (/^093\d{7,8}$/.test(local)) {
      return 'MecTel';
    } else if (
      /^092\d{6,7}$/.test(local) ||
      /^094\d{6,7}$/.test(local) ||
      /^095\d{6,7}$/.test(local)
    ) {
      return 'MPT';
    }

    return 'Unknown Operator';
  }
}
