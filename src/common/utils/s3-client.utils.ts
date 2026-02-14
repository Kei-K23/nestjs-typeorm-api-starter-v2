import {
  S3Client,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class S3ClientUtils {
  private readonly logger = new Logger(S3ClientUtils.name);
  private readonly s3Client: S3Client;
  private readonly bucketName: string;

  constructor(private readonly configService: ConfigService) {
    const AWS_ACCESS_KEY_ID =
      this.configService.get<string>('AWS_ACCESS_KEY_ID')!;
    const AWS_SECRET_ACCESS_KEY = this.configService.get<string>(
      'AWS_SECRET_ACCESS_KEY',
    )!;
    const AWS_REGION = this.configService.get<string>('AWS_REGION')!;
    const AWS_ENDPOINT = this.configService.get<string>('AWS_ENDPOINT')!;
    const AWS_BUCKET_NAME = this.configService.get<string>('AWS_BUCKET_NAME')!;

    this.bucketName = AWS_BUCKET_NAME;

    this.s3Client = new S3Client({
      region: AWS_REGION,
      endpoint: AWS_ENDPOINT,
      credentials: {
        accessKeyId: AWS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SECRET_ACCESS_KEY,
      },
      forcePathStyle: true,
    });
  }

  /**
   * Generate a presigned URL for a file in S3
   */
  async generatePresignedUrl(
    key: string,
    expiresIn: number = 3600,
  ): Promise<string | null> {
    try {
      if (!key || key.trim().length === 0) {
        return null;
      }
      const command = new GetObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      const url = await getSignedUrl(this.s3Client, command, { expiresIn });

      return url;
    } catch (error: unknown) {
      const err = error as Error;
      if (key && key.trim().length > 0) {
        this.logger.error(
          `Failed to generate download URL for ${key}: ${err.message}`,
          err.stack,
        );
      }
      return null;
    }
  }

  /**
   * Check if an object exists in S3
   */
  async objectExists(key: string): Promise<boolean> {
    try {
      if (!key || key.trim().length === 0) {
        return false;
      }
      const command = new HeadObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      await this.s3Client.send(command);
      return true;
    } catch (error) {
      const err = error as Error;
      if (key && key.trim().length > 0) {
        this.logger.error(
          `Failed to check object existence for ${key}: ${err.message}`,
          err.stack,
        );
      }
      return false;
    }
  }

  /**
   * Upload a file to S3
   */
  async uploadFile({
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {
    try {
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: `${path}/${key}`,
        Body: body,
        ContentType: contentType,
        Metadata: metadata,
      });

      await this.s3Client.send(command);

      this.logger.log(`Successfully uploaded file: ${key}`);
      return { success: true, key: `${path}/${key}` };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to upload file ${key}: ${err.message}`,
        err.stack,
      );
      return { success: false, error: err.message, key: `${path}/${key}` };
    }
  }

  /**
   * Update an existing file in S3
   * Note: This method overwrites the existing file with the new content.
   */
  async updateFile({
    oldKey,
    key,
    body,
    contentType,
    path,
    metadata,
  }: {
    key: string;
    oldKey: string;
    body: Buffer | Uint8Array | string;
    contentType?: string;
    path?: string;
    metadata?: Record<string, string>;
  }): Promise<{ success: boolean; key?: string; error?: string }> {
    const newKey = `${path}/${key}`;
    if (oldKey === key) {
      throw new Error('oldKey and key must be different');
    }

    if (!(await this.objectExists(oldKey))) {
      throw new Error(`oldKey ${oldKey} does not exist`);
    }

    try {
      const command = new PutObjectCommand({
        Bucket: this.bucketName,
        Key: newKey,
        Body: body,
        ContentType: contentType,
        Metadata: metadata,
      });

      await this.s3Client.send(command);
      this.logger.log(`Successfully updated file: ${key}`);
      // Delete old data
      await this.deleteObject(oldKey);

      return { success: true, key: newKey };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to update file ${key}: ${err.message}`,
        err.stack,
      );
      // When error occur and image is uploaded, rollback and delete new image
      await this.deleteObject(newKey);
      this.logger.error(
        `Rollback: Successfully deleted new uploaded file: ${newKey}`,
      );

      return { success: false, error: err.message, key: newKey };
    }
  }

  /**
   * Delete a file from S3
   */
  async deleteObject(
    key: string,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      if (!key || key.trim().length === 0) {
        return { success: false, error: 'Key is empty' };
      }
      const command = new DeleteObjectCommand({
        Bucket: this.bucketName,
        Key: key,
      });

      await this.s3Client.send(command);

      this.logger.log(`Successfully deleted file: ${key}`);
      return { success: true };
    } catch (error: unknown) {
      const err = error as Error;
      this.logger.error(
        `Failed to delete file ${key}: ${err.message}`,
        err.stack,
      );
      return { success: false, error: err.message };
    }
  }

  getKeyFromPresignedUrl(url: string): string | null {
    try {
      if (!url || url.trim().length === 0) return null;
      const u = new URL(url);
      const bucket = (this.bucketName || '').toLowerCase();
      const host = (u.host || '').toLowerCase();
      let pathname = u.pathname || '';
      if (!pathname) return null;
      if (pathname.startsWith('/')) pathname = pathname.slice(1);
      if (pathname.length === 0) return null;
      if (bucket && host.startsWith(`${bucket}.`)) {
        return decodeURIComponent(pathname);
      }
      const parts = pathname.split('/');
      if (bucket && parts[0].toLowerCase() === bucket && parts.length > 1) {
        return decodeURIComponent(parts.slice(1).join('/'));
      }
      return decodeURIComponent(pathname);
    } catch {
      return null;
    }
  }
}
