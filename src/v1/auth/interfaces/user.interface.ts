import { Admin } from 'src/v1/admin/entities/admin.entity';
import { User } from 'src/v1/user/entities/user.entity';

type StrippedAdmin = Omit<Admin, 'password' | 'generateUUID' | 'hashPassword'>;

type StrippedUser = Omit<User, 'password' | 'generateUUID' | 'hashPassword'>;

export type AuthenticatedAccount = (StrippedAdmin | StrippedUser) & {
  subjectType?: 'ADMIN' | 'USER';
  role?: StrippedAdmin['role'];
};

export type AuthenticatedUser = AuthenticatedAccount;

export interface RequestWithUser extends Request {
  params: any;
  user: AuthenticatedUser;
}

export interface JwtPayload {
  sub: string;
  subjectType: 'ADMIN' | 'USER';
  adminId?: string;
  userId?: string;
  roleId?: string;
  iat?: number;
  exp?: number;
}
