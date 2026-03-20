import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import {
  PERMISSIONS_KEY,
  PermissionRequirement,
} from '../decorators/permissions.decorator';
import {
  AuthenticatedUser,
  RequestWithUser,
} from '../interfaces/user.interface';
import { ActionType } from '../entities/permission.entity';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredPermissions = this.reflector.getAllAndOverride<
      PermissionRequirement[]
    >(PERMISSIONS_KEY, [context.getHandler(), context.getClass()]);

    if (!requiredPermissions) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<RequestWithUser>();

    if (!user || !user.role?.rolePermissions) {
      throw new ForbiddenException('Access denied: No permissions');
    }

    const hasPermission = requiredPermissions.every((requiredPermission) => {
      // Handle new object format
      return this.checkObjectPermission(requiredPermission, user);
    });

    if (!hasPermission) {
      throw new ForbiddenException('Access denied: Insufficient permissions');
    }

    return true;
  }

  private checkObjectPermission(
    requiredPermission: PermissionRequirement,
    user: AuthenticatedUser,
  ): boolean {
    const permissionTypeMap = {
      create: ActionType.CREATE,
      read: ActionType.READ,
      update: ActionType.UPDATE,
      delete: ActionType.DELETE,
    };

    const requiredPermissionType =
      permissionTypeMap[requiredPermission.permission];

    return !!user?.role?.rolePermissions?.some((rolePermission) => {
      const permission = rolePermission.permission;
      const module = permission?.module;

      return (
        module?.code === requiredPermission.module.toString() &&
        permission.action === requiredPermissionType
      );
    });
  }
}
