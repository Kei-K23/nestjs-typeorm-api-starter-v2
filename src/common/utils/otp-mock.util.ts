import { ConfigService } from '@nestjs/config';

export const DEFAULT_MOCK_OTP_CODE = '000000';

function parseBoolean(value: unknown): boolean | undefined {
  if (typeof value === 'boolean') {
    return value;
  }

  if (typeof value === 'string') {
    if (value.toLowerCase() === 'true') {
      return true;
    }

    if (value.toLowerCase() === 'false') {
      return false;
    }
  }

  return undefined;
}

export function isOtpMockEnabled(config: ConfigService): boolean {
  const explicitOtpMock = parseBoolean(config.get('OTP_MOCK_ENABLED'));
  if (explicitOtpMock !== undefined) {
    return explicitOtpMock;
  }

  if (config.get<string>('NODE_ENV', 'development') === 'development') {
    return true;
  }

  const explicitSmsMock = parseBoolean(config.get('SMS_MOCK_ENABLED'));
  if (explicitSmsMock !== undefined) {
    return explicitSmsMock;
  }

  return false;
}

export function getMockOtpCode(config: ConfigService): string {
  return config.get<string>('OTP_MOCK_CODE') || DEFAULT_MOCK_OTP_CODE;
}
