export interface SendTwoFactorCodePayload {
  code: string;
  email: string;
  userName: string;
  fromUsername: string;
  expiresIn: number;
}

export interface SendForgotPasswordResetCodePayload {
  code: string;
  email: string;
  userName: string;
  fromUsername: string;
  expiresIn: number;
}

export interface SendOtpPayload {
  to: string;
  message: string;
  ttl?: number;
  pinLength?: number;
  brand?: string;
  from?: string;
}

export interface VerifyOtpPayload {
  requestId: string;
  code: string;
}
