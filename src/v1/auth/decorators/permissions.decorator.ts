import { SetMetadata } from '@nestjs/common';
import { PermissionModule } from '../entities/permission.entity';

export const PERMISSIONS_KEY = 'permissions';

export interface PermissionRequirement {
  module: PermissionModule;
  permission: 'create' | 'read' | 'update' | 'delete';
}

// Access is granted if the admin's role satisfies ANY of the listed permissions (OR semantics).
// See PermissionsGuard for enforcement logic.
export const RequirePermissions = (...permissions: PermissionRequirement[]) =>
  SetMetadata(PERMISSIONS_KEY, permissions);
