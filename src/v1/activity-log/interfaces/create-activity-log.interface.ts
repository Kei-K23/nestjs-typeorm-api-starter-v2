import { ActivityAction } from '../entities/user-activity-log.entity';

export interface CreateActivityLogData {
  userId?: string | null;
  adminId?: string | null;
  action: ActivityAction;
  description: string;
  resourceType?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  device?: string;
  browser?: string;
  os?: string;
  location?: string;
  isActivityLog: boolean;
  metadata?: Record<string, unknown>;
}
