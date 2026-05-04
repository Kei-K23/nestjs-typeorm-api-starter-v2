import * as Joi from 'joi';

export const envValidationSchema = Joi.object({
  NODE_ENV: Joi.string()
    .valid('development', 'production', 'test')
    .default('development'),
  PORT: Joi.number().default(3000),
  APP_NAME: Joi.string().default('NestJS TypeORM API Starter'),

  // Database
  DB_HOST: Joi.string().required(),
  DB_PORT: Joi.number().default(5432),
  DB_USERNAME: Joi.string().required(),
  DB_PASSWORD: Joi.string().required(),
  DB_NAME: Joi.string().required(),

  // Auth
  AUTH_PASSWORD_SALT_ROUNDS: Joi.number().default(10),

  // JWT — secrets must be at least 32 characters
  JWT_SECRET: Joi.string().min(32).required(),
  JWT_REFRESH_SECRET: Joi.string().min(32).required(),
  JWT_EXPIRATION: Joi.number().default(900000), // 15 minutes
  JWT_REFRESH_EXPIRATION: Joi.number().default(2592000000), // 30 days

  // Redis
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().default(6379),

  // CORS
  CORS_ORIGINS: Joi.string().optional(),

  // AWS S3 (optional — only required when file uploads are used)
  AWS_ACCESS_KEY_ID: Joi.string().optional(),
  AWS_SECRET_ACCESS_KEY: Joi.string().optional(),
  AWS_REGION: Joi.string().optional(),
  AWS_BUCKET_NAME: Joi.string().optional(),
  AWS_ENDPOINT: Joi.string().optional(),

  // Email
  SMTP_FROM_NAME: Joi.string().optional(),

  // OTP
  OTP_MOCK_ENABLED: Joi.boolean().optional(),
  OTP_MOCK_CODE: Joi.string()
    .pattern(/^\d{6}$/)
    .default('000000'),

  // SMS
  SMS_POH_API_KEY: Joi.string().optional(),
  SMS_POH_API_SECRET_KEY: Joi.string().optional(),
  SMS_POH_BASE_API_URL: Joi.string().optional(),
  SMS_POH_API_BRAND: Joi.string().optional(),
  SMS_POH_API_SENDER_ID: Joi.string().optional(),

  // Set to true to skip real SMS calls outside the default development mock
  SMS_MOCK_ENABLED: Joi.boolean().default(false),
}).options({ allowUnknown: true });
