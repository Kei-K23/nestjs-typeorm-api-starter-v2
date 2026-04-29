import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable } from 'rxjs';
import { switchMap } from 'rxjs/operators';
import { PRESIGNED_URLS_KEY } from '../decorators/presigned-urls.decorator';
import { S3ClientUtils } from '../utils/s3-client.utils';

@Injectable()
export class PresignedUrlInterceptor implements NestInterceptor {
  constructor(
    private readonly reflector: Reflector,
    private readonly s3ClientUtils: S3ClientUtils,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const fields = this.reflector.getAllAndOverride<string[]>(
      PRESIGNED_URLS_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!fields?.length) return next.handle();

    return next.handle().pipe(
      switchMap(async (response) => {
        if (!response?.success) return response;

        const { data } = response;
        if (!data) return response;

        if (Array.isArray(data)) {
          await Promise.all(data.map((item) => this.transformFields(item, fields)));
        } else {
          await this.transformFields(data, fields);
        }

        return response;
      }),
    );
  }

  private async transformFields(
    obj: Record<string, any>,
    fields: string[],
  ): Promise<void> {
    await Promise.all(
      fields.map(async (fieldPath) => {
        const parts = fieldPath.split('.');
        let target: Record<string, any> = obj;
        for (let i = 0; i < parts.length - 1; i++) {
          target = target?.[parts[i]] as Record<string, any>;
          if (!target) return;
        }
        const lastKey = parts[parts.length - 1];
        if (target?.[lastKey]) {
          target[lastKey] =
            (await this.s3ClientUtils.generatePresignedUrl(
              target[lastKey] as string,
            )) ?? '';
        }
      }),
    );
  }
}
