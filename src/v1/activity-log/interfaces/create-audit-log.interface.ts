import { LogAction } from '../constants/log-action.enum';
import { LogStatus } from '../constants/log-status.enum';

export interface CreateAuditLogData {
  adminId?: string | null;
  action: LogAction;
  description: string;
  entityName?: string;
  entityId?: string;
  oldValue?: Record<string, unknown>;
  newValue?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  device?: string;
  browser?: string;
  os?: string;
  location?: string;
  status?: LogStatus;
  metadata?: Record<string, unknown>;
}
