import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ResponseUtil } from '../utils/response.util';
import { ApiResponse } from '../interfaces/api-response.interface';
import { Request, Response } from 'express';

@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<
  T,
  ApiResponse<T>
> {
  intercept(
    context: ExecutionContext,
    next: CallHandler,
  ): Observable<ApiResponse<T>> {
    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();

    return next.handle().pipe(
      map((data): ApiResponse<T> => {
        // If data is already a formatted response, return as is
        if (data && typeof data === 'object' && 'success' in data) {
          return data as ApiResponse<T>; // type assertion here
        }

        // Get the status code from response
        const statusCode = response.statusCode;

        // Determine message based on HTTP method and status
        let message = 'Operation successful';
        if (request.method === 'POST' && statusCode === 201) {
          message = 'Resource created successfully';
        } else if (request.method === 'PUT' || request.method === 'PATCH') {
          message = 'Resource updated successfully';
        } else if (request.method === 'DELETE') {
          message = 'Resource deleted successfully';
        } else if (request.method === 'GET') {
          message = 'Data retrieved successfully';
        }

        return ResponseUtil.success(
          data,
          message,
          statusCode,
        ) as ApiResponse<T>;
      }),
    );
  }
}
