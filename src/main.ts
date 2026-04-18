import { NestFactory, Reflector } from '@nestjs/core';
import {
  ClassSerializerInterceptor,
  ValidationPipe,
  VersioningType,
} from '@nestjs/common';
import { AppModule } from './app.module';
import { HttpExceptionFilter } from './common/filters/http-exception.filter';
import { WinstonModule } from 'nest-winston';
import { winstonConfig } from './common/config/logger.config';
import helmet from 'helmet';
import { ConfigService } from '@nestjs/config';
async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: WinstonModule.createLogger(winstonConfig),
  });

  const configService = app.get(ConfigService);
  const isProduction = configService.get('NODE_ENV') === 'production';

  // Security headers with Helmet — CSP enabled with sensible defaults
  // For Swagger UI in development, 'unsafe-inline' is needed for scripts/styles
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", ...(isProduction ? [] : ["'unsafe-inline'"])],
          imgSrc: ["'self'", 'data:', 'https:'],
          scriptSrc: ["'self'", ...(isProduction ? [] : ["'unsafe-inline'"])],
        },
      },
    }),
  );

  // Environment-based CORS configuration
  const envOriginsRaw = configService.get<string>('CORS_ORIGINS');
  let origins: string[] | boolean = [];

  if (envOriginsRaw) {
    const parsed = envOriginsRaw
      .split(',')
      .map((o) => o.trim())
      .filter((o) => o.length > 0);
    if (parsed.length === 1) {
      const val = parsed[0].toLowerCase();
      if (val === '*' || val === 'all' || val === 'true') {
        origins = true;
        console.warn(
          '[SECURITY WARNING] CORS is configured to allow ALL origins. ' +
            'This is only acceptable in local development. ' +
            'Set CORS_ORIGINS to specific domains in production.',
        );
      } else {
        origins = parsed;
      }
    } else if (parsed.length > 1) {
      origins = parsed;
    }
  }

  app.enableCors({
    origin: origins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'x-signature',
      'x-timestamp',
      'x-request-id',
      'Accept',
      'Origin',
    ],
    exposedHeaders: ['X-Request-ID'],
    credentials: true,
  });

  // Enable global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  // Enable global serialization
  app.useGlobalInterceptors(new ClassSerializerInterceptor(app.get(Reflector)));

  // Apply global exception filter
  app.useGlobalFilters(new HttpExceptionFilter());

  // Set global API prefix — produces /api/v1/... with URI versioning
  app.setGlobalPrefix('api');

  // Enable URI-based versioning (/api/v1/...)
  app.enableVersioning({
    type: VersioningType.URI,
  });

  // Enable graceful shutdown — triggers OnModuleDestroy across all modules
  app.enableShutdownHooks();

  const port = configService.get<number>('PORT', 3000);
  const server = await app.listen(port);

  console.log(`Application is running on port ${port}`);
  console.log(`Environment: ${configService.get('NODE_ENV', 'development')}`);

  // Graceful shutdown on SIGTERM (container restarts, PM2 reloads)
  process.on('SIGTERM', async () => {
    console.log('SIGTERM received. Shutting down gracefully...');
    await app.close();
    server.close(() => {
      console.log('HTTP server closed.');
      process.exit(0);
    });
  });
}
bootstrap();
