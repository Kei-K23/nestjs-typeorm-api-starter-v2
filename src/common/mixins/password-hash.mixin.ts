// This file is intentionally unused.
// Password hashing logic is shared via hashPasswordIfNeeded() in:
//   src/common/utils/password-hash.util.ts
//
// Each entity that needs password hashing declares its own @BeforeInsert/@BeforeUpdate
// hook and delegates to that utility. This avoids TypeScript abstract-mixin issues
// while keeping the hashing logic in a single place.
