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

@Catch()
export class HttpExceptionFilter implements ExceptionFilter {
  private readonly logger = new Logger(HttpExceptionFilter.name);
  catch(exception: unknown, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse<Response>();

    let status = HttpStatus.INTERNAL_SERVER_ERROR;
    let message = 'Internal server error';
    let details: any = null;

    if (exception instanceof HttpException) {
      status = exception.getStatus();
      const exceptionResponse = exception.getResponse();

      if (typeof exceptionResponse === 'object') {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        message = (exceptionResponse as any).message || exception.message;
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
        details = (exceptionResponse as any).details || null;

        // Handle validation errors
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        if (Array.isArray((exceptionResponse as any).message)) {
          message = 'Validation failed';
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
          details = (exceptionResponse as any).message;
        }
      } else {
        message = exceptionResponse;
      }
    } else if (exception instanceof QueryFailedError) {
      // Handle database errors such as Postgres unique constraint violations
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
      const driverError: any = (exception as any).driverError || exception;
      if (driverError?.code === '23505') {
        status = HttpStatus.CONFLICT;
        const detail: string = driverError.detail || 'Duplicate key value';
        const parsed = this.parseUniqueConstraintDetail(detail);
        message = parsed.field
          ? `${parsed.field} already exists`
          : 'Duplicate value violates unique constraint';
        details = {
          // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
          constraint: driverError.constraint,
          detail,
          field: parsed.field,
          value: parsed.value,
        };
      } else {
        message = exception.message;
      }
    } else if ((exception as any)?.code === '23505') {
      // In case the raw PG error bubbles up without TypeORM wrapper
      status = HttpStatus.CONFLICT;
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const detail: string = (exception as any).detail || 'Duplicate key value';
      const parsed = this.parseUniqueConstraintDetail(detail);
      message = parsed.field
        ? `${parsed.field} already exists`
        : 'Duplicate value violates unique constraint';
      details = {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
        constraint: (exception as any).constraint,
        detail,
        field: parsed.field,
        value: parsed.value,
      };
    } else if (exception instanceof Error) {
      message = exception.message;
    }

    // Log the error
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

  private getErrorName(status: number): string {
    switch (status) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
      case HttpStatus.BAD_REQUEST:
        return 'Bad Request';
      // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
      case HttpStatus.UNAUTHORIZED:
        return 'Unauthorized';
      // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
      case HttpStatus.FORBIDDEN:
        return 'Forbidden';
      // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
      case HttpStatus.NOT_FOUND:
        return 'Not Found';
      // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
      case HttpStatus.UNPROCESSABLE_ENTITY:
        return 'Validation Error';
      // eslint-disable-next-line @typescript-eslint/no-unsafe-enum-comparison
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
    // Typical Postgres detail: "Key (email)=(test@example.com) already exists."
    const match = /Key \((.+)\)=\((.+)\) already exists\./.exec(detail);
    if (match && match.length >= 3) {
      return { field: match[1], value: match[2] };
    }
    return {};
  }
}
