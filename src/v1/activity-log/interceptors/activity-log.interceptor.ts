import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { ActivityLogService } from '../services/activity-log.service';
import { ActivityAction } from '../entities/user-activity-log.entity';
import { Reflector } from '@nestjs/core';
import { RequestWithUser } from 'src/v1/auth/interfaces/user.interface';
import { Request } from 'express';
import { parseUserAgent } from 'src/common/utils/user-agent.util';

export const LOG_ACTIVITY_KEY = 'logActivity';

export interface ActivityLogOptions {
  action: ActivityAction;
  description: string;
  resourceType?: string;
  getResourceId?: (result: any, req: any) => string;
}

@Injectable()
export class ActivityLogInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ActivityLogInterceptor.name);

  constructor(
    private readonly activityLogService: ActivityLogService,
    private readonly reflector: Reflector,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const logOptions = this.reflector.get<ActivityLogOptions>(
      LOG_ACTIVITY_KEY,
      context.getHandler(),
    );

    if (!logOptions) {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest<RequestWithUser>();
    const user = request.user;

    if (!user) {
      return next.handle();
    }

    return next.handle().pipe(
      tap((result) => {
        this.logActivity(
          result,
          request as unknown as Request,
          logOptions,
        ).catch((error) => {
          this.logger.error('Failed to log activity:', error);
        });
      }),
    );
  }

  private async logActivity(
    result: any,
    request: Request,
    logOptions: ActivityLogOptions,
  ): Promise<void> {
    try {
      const requestWithUser = request as unknown as RequestWithUser;

      const { device, browser, os } = parseUserAgent(request);

      const resourceId = logOptions.getResourceId
        ? logOptions.getResourceId(result, request)
        : request?.params?.id;

      const subject = requestWithUser.user;

      const payload: Record<string, unknown> = {
        action: logOptions.action,
        description: logOptions.description,
        resourceType: logOptions.resourceType,
        resourceId,
        ipAddress: this.getClientIp(request),
        userAgent: request?.headers?.['user-agent'] || '',
        device,
        browser,
        os,
        metadata: {
          method: request.method,
          url: request.url,
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          body: request.method !== 'GET' ? request.body : undefined,
        },
      };

      if (subject.subjectType === 'ADMIN') {
        payload.adminId = subject.id;
      } else {
        payload.userId = subject.id;
      }

      await this.activityLogService.create({
        ...payload,
      });
      this.logger.log(
        `Activity logged: ${logOptions.action} ${logOptions.description} for resource ${resourceId}`,
      );
    } catch (error) {
      this.logger.error('Failed to log activity:', error);
    }
  }

  private getClientIp(request: Request): string {
    const expressRequest = request as any as Request;
    return (
      (request.headers['x-forwarded-for'] as string) ||
      (request.headers['x-real-ip'] as string) ||
      expressRequest.connection?.remoteAddress ||
      expressRequest.socket?.remoteAddress ||
      expressRequest.ip ||
      'unknown'
    );
  }
}
