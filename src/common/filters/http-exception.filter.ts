import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Response } from 'express';
import { QueryFailedError } from 'typeorm';
import { ResponseUtil } from '../utils/response.util';

interface HttpExceptionResponseObject {
  message?: string | string[];
  details?: unknown;
  statusCode?: number;
  error?: string;
}

interface PostgresDriverError {
  code?: string;
  detail?: string;
  constraint?: string;
}

type QueryFailedErrorWithDriver = QueryFailedError & {
  driverError?: PostgresDriverError;
};

type RawPostgresError = Error & PostgresDriverError;

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);

  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let details: unknown = null;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'object') {
        const responseObj = exceptionResponse as HttpExceptionResponseObject;
        message = Array.isArray(responseObj.message)
          ? 'Validation failed'
          : (responseObj.message ?? exception.message);
        details = Array.isArray(responseObj.message)
          ? responseObj.message
          : (responseObj.details ?? null);
      } else {
        message = exceptionResponse as string;
      }
    } else if (exception instanceof QueryFailedError) {
      const driverError = (exception as QueryFailedErrorWithDriver).driverError;
      if (driverError?.code === '23505') {
        status = HttpStatus.CONFLICT;
        const detail = driverError.detail ?? 'Duplicate key value';
        const parsed = this.parseUniqueConstraintDetail(detail);
        message = parsed.field
          ? `${parsed.field} already exists`
          : 'Duplicate value violates unique constraint';
        details = {
          constraint: driverError.constraint,
          detail,
          field: parsed.field,
          value: parsed.value,
        };
      } else {
        message = exception.message;
      }
    } else if (this.isRawPostgresError(exception) && exception.code === '23505') {
      status = HttpStatus.CONFLICT;
      const detail = exception.detail ?? 'Duplicate key value';
      const parsed = this.parseUniqueConstraintDetail(detail);
      message = parsed.field
        ? `${parsed.field} already exists`
        : 'Duplicate value violates unique constraint';
      details = {
        constraint: exception.constraint,
        detail,
        field: parsed.field,
        value: parsed.value,
      };
    } else if (exception instanceof Error) {
      message = exception.message;
    }

    this.logger.error(
      `HTTP Exception: ${message}`,
      exception instanceof Error ? exception.stack : undefined,
    );

    const errorResponse = ResponseUtil.error(
      message,
      status,
      this.getErrorName(status),
      details,
    );

    response.status(status).json(errorResponse);
  }

  private isRawPostgresError(err: unknown): err is RawPostgresError {
    return (
      err instanceof Error &&
      'code' in err &&
      typeof (err as Record<string, unknown>).code === 'string'
    );
  }

  private getErrorName(status: number): string {
    switch (status) {
      case HttpStatus.BAD_REQUEST:
        return 'Bad Request';
      case HttpStatus.UNAUTHORIZED:
        return 'Unauthorized';
      case HttpStatus.FORBIDDEN:
        return 'Forbidden';
      case HttpStatus.NOT_FOUND:
        return 'Not Found';
      case HttpStatus.CONFLICT:
        return 'Conflict';
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'Validation Error';
      case HttpStatus.INTERNAL_SERVER_ERROR:
        return 'Internal Server Error';
      default:
        return 'Error';
    }
  }

  private parseUniqueConstraintDetail(detail: string): {
    field?: string;
    value?: string;
  } {
    const match = /Key \((.+)\)=\((.+)\) already exists\./.exec(detail);
    if (match && match.length >= 3) {
      return { field: match[1], value: match[2] };
    }
    return {};
  }
}
