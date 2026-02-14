import { HttpStatus } from '@nestjs/common';
import {
  ApiResponse,
  ResponseMeta,
  ErrorResponse,
} from '../interfaces/api-response.interface';

export class ResponseUtil {
  /**
   * Create a successful response
   */
  static success<T>(
    data: T,
    message: string = 'Operation successful',
    statusCode: number = HttpStatus.OK,
    meta?: ResponseMeta,
    apiVersion: 'v1' | 'v2' | 'v3' = 'v1',
  ): ApiResponse<T> {
    return {
      success: true,
      statusCode,
      message,
      data,
      meta,
      apiVersion,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Create a successful response for created resources
   */
  static created<T>(
    data: T,
    message: string = 'Resource created successfully',
  ): ApiResponse<T> {
    return this.success(data, message, HttpStatus.CREATED);
  }

  /**
   * Create a successful response for updated resources
   */
  static updated<T>(
    data: T,
    message: string = 'Resource updated successfully',
  ): ApiResponse<T> {
    return this.success(data, message, HttpStatus.OK);
  }

  /**
   * Create a successful response for deleted resources
   */
  static deleted(
    message: string = 'Resource deleted successfully',
  ): ApiResponse<null> {
    return this.success(null, message, HttpStatus.OK);
  }

  /**
   * Create a paginated response
   */
  static paginated<T>(
    data: T[],
    total: number,
    page: number,
    limit: number,
    message: string = 'Data retrieved successfully',
  ): ApiResponse<T[]> {
    const totalPages = Math.ceil(total / limit);

    return this.success(data, message, HttpStatus.OK, {
      total,
      page,
      limit,
      totalPages,
    });
  }

  /**
   * Create an error response
   */
  static error(
    message: string,
    statusCode: number = HttpStatus.INTERNAL_SERVER_ERROR,
    error: string = 'Internal Server Error',
    details?: any,
    apiVersion: 'v1' | 'v2' | 'v3' = 'v1',
  ): ErrorResponse {
    return {
      success: false,
      statusCode,
      message,
      error,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      details,
      apiVersion,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Create a bad request error response
   */
  static badRequest(
    message: string = 'Bad Request',
    details?: any,
  ): ErrorResponse {
    return this.error(message, HttpStatus.BAD_REQUEST, 'Bad Request', details);
  }

  /**
   * Create a not found error response
   */
  static notFound(message: string = 'Resource not found'): ErrorResponse {
    return this.error(message, HttpStatus.NOT_FOUND, 'Not Found');
  }

  /**
   * Create an unauthorized error response
   */
  static unauthorized(message: string = 'Unauthorized access'): ErrorResponse {
    return this.error(message, HttpStatus.UNAUTHORIZED, 'Unauthorized');
  }

  /**
   * Create a forbidden error response
   */
  static forbidden(message: string = 'Access forbidden'): ErrorResponse {
    return this.error(message, HttpStatus.FORBIDDEN, 'Forbidden');
  }

  /**
   * Create a validation error response
   */
  static validationError(
    message: string = 'Validation failed',
    details?: any,
  ): ErrorResponse {
    return this.error(
      message,
      HttpStatus.UNPROCESSABLE_ENTITY,
      'Validation Error',
      details,
    );
  }
}
