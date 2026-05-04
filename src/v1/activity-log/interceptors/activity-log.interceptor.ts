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
import { AuditLogService } from '../services/audit-log.service';
import { LogAction } from '../constants/log-action.enum';
import { Reflector } from '@nestjs/core';
import { RequestWithUser } from 'src/v1/auth/interfaces/user.interface';
import { Request } from 'express';
import { parseUserAgent } from 'src/common/utils/user-agent.util';
import { consumeAuditLogMetadata } from '../utils/audit-log-metadata.util';

export const LOG_ACTIVITY_KEY = 'logActivity';

export interface ActivityLogOptions {
  action: LogAction;
  description: string;
  resourceType?: string;
  getResourceId?: (result: unknown, req: Request) => string | undefined;
}

@Injectable()
export class ActivityLogInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ActivityLogInterceptor.name);

  constructor(
    private readonly activityLogService: ActivityLogService,
    private readonly auditLogService: AuditLogService,
    private readonly reflector: Reflector,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
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
        ).catch((error) => this.logger.error('Failed to log activity:', error));
      }),
    );
  }

  private async logActivity(
    result: unknown,
    request: Request,
    logOptions: ActivityLogOptions,
  ): Promise<void> {
    try {
      const requestWithUser = request as unknown as RequestWithUser;
      const subject = requestWithUser.user;
      const { device, browser, os } = parseUserAgent(request);

      const responseData = this.getResponseData(result);
      const resourceId =
        (logOptions.getResourceId
          ? (logOptions.getResourceId(responseData, request) ??
            logOptions.getResourceId(result, request))
          : undefined) ??
        this.getResourceId(responseData) ??
        request.params?.id;
      const auditMetadata = consumeAuditLogMetadata(responseData);

      const context = {
        action: logOptions.action,
        description: logOptions.description,
        resourceType: logOptions.resourceType,
        resourceId,
        ipAddress: this.getClientIp(request),
        userAgent: (request.headers['user-agent'] as string) || '',
        device,
        browser,
        os,
        location: (request.headers['cf-ipcountry'] as string) || undefined,
        metadata: {
          method: request.method,
          url: request.url,
          body:
            request.method !== 'GET'
              ? this.sanitizeBody(request.body as Record<string, unknown>)
              : undefined,
        },
      };

      if (subject.subjectType === 'ADMIN') {
        await this.auditLogService.create({
          adminId: subject.id,
          action: context.action,
          description: context.description,
          entityName: context.resourceType,
          entityId: resourceId,
          oldValue: this.sanitizeOptionalRecord(auditMetadata.oldValue),
          newValue: this.sanitizeOptionalRecord(auditMetadata.newValue),
          ipAddress: context.ipAddress,
          userAgent: context.userAgent,
          device: context.device,
          browser: context.browser,
          os: context.os,
          location: context.location,
          metadata: context.metadata,
        });
      } else {
        await this.activityLogService.create({
          userId: subject.id,
          ...context,
        });
      }

      this.logger.log(
        `${subject.subjectType} activity logged: ${logOptions.action} for resource ${resourceId}`,
      );
    } catch (error) {
      this.logger.error('Failed to log activity:', error);
    }
  }

  private getResponseData(result: unknown): unknown {
    if (!result || typeof result !== 'object') return result;

    if ('data' in result) {
      return (result as { data?: unknown }).data;
    }

    return result;
  }

  private getResourceId(result: unknown): string | undefined {
    if (!result || typeof result !== 'object') return undefined;

    const id = (result as { id?: unknown }).id;
    return typeof id === 'string' || typeof id === 'number'
      ? id.toString()
      : undefined;
  }

  private readonly SENSITIVE_KEYS = new Set([
    'password',
    'currentPassword',
    'newPassword',
    'confirmPassword',
    'token',
    'accessToken',
    'refreshToken',
    'otp',
    'code',
    'secret',
  ]);

  private sanitizeBody(body: Record<string, unknown>): Record<string, unknown> {
    if (!body || typeof body !== 'object') return body;
    return Object.fromEntries(
      Object.entries(body).map(([key, value]) => [
        key,
        this.SENSITIVE_KEYS.has(key)
          ? '[REDACTED]'
          : typeof value === 'object' && value !== null
            ? this.sanitizeBody(value as Record<string, unknown>)
            : value,
      ]),
    );
  }

  private sanitizeOptionalRecord(
    body?: Record<string, unknown>,
  ): Record<string, unknown> | undefined {
    return body ? this.sanitizeBody(body) : undefined;
  }

  private getClientIp(request: Request): string {
    const forwarded = request.headers['x-forwarded-for'] as string;
    return (
      forwarded?.split(',')[0]?.trim() ||
      (request.headers['x-real-ip'] as string) ||
      request.socket?.remoteAddress ||
      request.ip ||
      'unknown'
    );
  }
}
