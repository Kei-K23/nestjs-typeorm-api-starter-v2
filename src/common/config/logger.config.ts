import { utilities as nestWinstonModuleUtilities } from 'nest-winston';
import * as winston from 'winston';
import 'winston-daily-rotate-file';

export const winstonConfig = {
  transports: [
    // Console logs
    new winston.transports.Console({
      level: 'debug',
      format: winston.format.combine(
        winston.format.timestamp(),
        nestWinstonModuleUtilities.format.nestLike(process.env.APP_NAME, {
          prettyPrint: true,
        }),
      ),
    }),

    // Daily rotating file logs
    new winston.transports.DailyRotateFile({
      level: 'info',
      dirname: 'logs', // directory to save log files
      filename: 'application-%DATE%.log',
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '14d', // keep logs for 14 days
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
    }),

    // Separate error logs (optional)
    new winston.transports.File({
      level: 'error',
      dirname: 'logs',
      filename: 'errors.log',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
    }),
  ],
};
