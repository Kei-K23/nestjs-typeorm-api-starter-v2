import { SetMetadata } from '@nestjs/common';
import { PermissionModule } from '../entities/permission.entity';

export const PERMISSIONS_KEY = 'permissions';

export interface PermissionRequirement {
  module: PermissionModule;
  permission: 'create' | 'read' | 'update' | 'delete';
}

export const RequirePermissions = (
  ...permissions: (PermissionRequirement | PermissionRequirement[])[]
) => {
  const flatPermissions: PermissionRequirement[] = permissions.flatMap(
    (permission) => (Array.isArray(permission) ? permission : [permission]),
  );
  return SetMetadata(PERMISSIONS_KEY, flatPermissions);
};
