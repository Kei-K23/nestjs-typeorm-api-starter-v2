import { AuthenticatedUser } from '../auth/interfaces/user.interface';

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}
