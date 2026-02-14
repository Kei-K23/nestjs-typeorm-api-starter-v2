export interface ApiResponse<T = any> {
  success: boolean;
  statusCode: number;
  message: string;
  data?: T;
  meta?: ResponseMeta;
  timestamp: string;
  apiVersion: 'v1' | 'v2' | 'v3';
}

export interface ResponseMeta {
  total?: number;
  page?: number;
  limit?: number;
  totalPages?: number;
}

export interface ErrorResponse {
  success: false;
  statusCode: number;
  message: string;
  error: string;
  details?: any;
  timestamp: string;
  apiVersion: 'v1' | 'v2' | 'v3';
}
