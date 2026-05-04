import * as bcrypt from 'bcryptjs';

const BCRYPT_HASH_PATTERN = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

export async function hashPasswordIfNeeded(
  password: string,
): Promise<string> {
  if (!password || BCRYPT_HASH_PATTERN.test(password)) {
    return password;
  }
  const rounds = Number(process.env.AUTH_PASSWORD_SALT_ROUNDS ?? 10);
  return bcrypt.hash(password, rounds);
}
