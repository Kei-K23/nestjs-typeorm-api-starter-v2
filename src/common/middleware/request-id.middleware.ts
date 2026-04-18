import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'crypto';

@Injectable()
export class RequestIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const requestId =
      (req.headers['x-request-id'] as string | undefined) || randomUUID();
    (req as Request & { requestId: string }).requestId = requestId;
    res.setHeader('X-Request-ID', requestId);
    next();
  }
}
