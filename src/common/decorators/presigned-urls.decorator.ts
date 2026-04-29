import { SetMetadata } from '@nestjs/common';

export const PRESIGNED_URLS_KEY = 'presignedUrlFields';

export const ResolvePresignedUrls = (...fields: string[]) =>
  SetMetadata(PRESIGNED_URLS_KEY, fields);
