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

  // Implement security headers with Helmet
  app.use(helmet({ contentSecurityPolicy: false }));

  // Environment-based CORS configuration
  const configService = app.get(ConfigService);
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
      } else {
        origins = parsed;
      }
    } else if (parsed.length > 1) {
      origins = parsed;
    }
  }

  // Environment-based CORS configuration
  const corsOptions = {
    origin: origins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Requested-With',
      'x-signature',
      'x-timestamp',
      'Accept',
      'Origin',
    ],
    credentials: true,
  };

  app.enableCors(corsOptions);

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

  // Enable versioning
  app.enableVersioning({
    type: VersioningType.URI,
  });

  // Start the application
  await app.listen(process.env.PORT ?? 3000);
  console.log(`Application is running on port ${process.env.PORT ?? 3000}`);
}
bootstrap();
