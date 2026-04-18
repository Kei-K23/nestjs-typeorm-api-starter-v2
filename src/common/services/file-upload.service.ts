import { Injectable } from '@nestjs/common';
import { randomUUID } from 'crypto';
import { S3ClientUtils } from '../utils/s3-client.utils';

@Injectable()
export class FileUploadService {
  constructor(private readonly s3ClientUtils: S3ClientUtils) {}

  /**
   * Uploads a profile image to S3 and returns the stored object key.
   * Returns null if the upload fails.
   */
  async uploadProfileImage(
    file: Express.Multer.File,
    path: 'users/profile' | 'admins/profile',
  ): Promise<string | null> {
    const original = file.originalname?.trim() || 'profile';
    const sanitized = original.replace(/[^a-zA-Z0-9_.-]/g, '_');
    const key = `${randomUUID()}-${sanitized}`;

    const res = await this.s3ClientUtils.uploadFile({
      key,
      body: file.buffer,
      contentType: file.mimetype,
      path,
      metadata: { filename: original },
    });

    return res.success && res.key ? res.key : null;
  }
}
