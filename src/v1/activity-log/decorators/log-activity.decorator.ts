import { SetMetadata } from '@nestjs/common';
import {
  ActivityLogOptions,
  LOG_ACTIVITY_KEY,
} from '../interceptors/activity-log.interceptor';

export const LogActivity = (options: ActivityLogOptions) =>
  SetMetadata(LOG_ACTIVITY_KEY, options);
