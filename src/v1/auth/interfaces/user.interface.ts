import { Admin } from 'src/v1/admin/entities/admin.entity';
import { User } from 'src/v1/user/entities/user.entity';

type StrippedAdmin = Omit<Admin, 'password' | 'generateUUID' | 'hashPassword'>;
type StrippedUser = Omit<User, 'password' | 'generateUUID' | 'hashPassword'>;

export type AuthenticatedUser = (StrippedAdmin | StrippedUser) & {
  subjectType?: 'ADMIN' | 'USER';
  role?: StrippedAdmin['role'];
};

export interface RequestWithUser extends Request {
  params: Record<string, string>;
  user: AuthenticatedUser;
}

export type AdminJwtPayload = {
  sub: string;
  subjectType: 'ADMIN';
  adminId: string;
  roleId: string;
  iat?: number;
  exp?: number;
};

export type UserJwtPayload = {
  sub: string;
  subjectType: 'USER';
  userId: string;
  iat?: number;
  exp?: number;
};

export type JwtPayload = AdminJwtPayload | UserJwtPayload;
