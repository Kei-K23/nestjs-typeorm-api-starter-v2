import { Module, Global } from '@nestjs/common';
import { ResponseInterceptor } from './interceptors/response.interceptor';
import { HttpExceptionFilter } from './filters/http-exception.filter';
import { S3ClientUtils } from './utils/s3-client.utils';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Setting } from 'src/v1/setting/entities/setting.entity';
import { EmailServiceUtils } from './utils/email-service.utils';

@Global()
@Module({
  imports: [TypeOrmModule.forFeature([Setting])],
  providers: [
    ResponseInterceptor,
    HttpExceptionFilter,
    S3ClientUtils,
    EmailServiceUtils,
  ],
  exports: [
    ResponseInterceptor,
    HttpExceptionFilter,
    S3ClientUtils,
    EmailServiceUtils,
  ],
})
export class CommonModule {}
