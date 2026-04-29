import { memoryStorage } from 'multer';

export const profileImageInterceptorOptions: Parameters<typeof import('@nestjs/platform-express').FileInterceptor>[1] = {
  storage: memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (
    _req: Express.Request,
    file: Express.Multer.File,
    cb: (error: Error | null, acceptFile: boolean) => void,
  ) => {
    if (!file?.mimetype) return cb(null, false);
    cb(null, true);
  },
};
