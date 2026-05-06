import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';
import duration from 'dayjs/plugin/duration';
import isBetween from 'dayjs/plugin/isBetween';

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.extend(duration);
dayjs.extend(isBetween);

// ─── Constants ────────────────────────────────────────────────────────────────

export const MYANMAR_TZ = 'Asia/Yangon'; // UTC+6:30, no DST

export const OTP_TTL_MINUTES = 10;
export const REFRESH_TOKEN_TTL_DAYS = 30;
export const LOG_RETENTION_DAYS = 90;
export const SMTP_CACHE_TTL_MS = 5 * 60 * 1000;

// ─── Current time ─────────────────────────────────────────────────────────────

/** Current time as a UTC Date. Use this everywhere instead of `new Date()`. */
export function nowUtc(): Date {
  return dayjs.utc().toDate();
}

/** Current time as a UTC ISO 8601 string (e.g. for API response timestamps). */
export function nowIso(): string {
  return dayjs.utc().toISOString();
}

/** Current time formatted for display in Myanmar local time. */
export function nowMyanmarDisplay(format = 'YYYY-MM-DD HH:mm:ss'): string {
  return dayjs.utc().tz(MYANMAR_TZ).format(format);
}

// ─── Future/past date helpers ─────────────────────────────────────────────────

/**
 * Returns a UTC Date N minutes from now (or from a given base date).
 * Use for OTP / 2FA expiry: `addMinutes(OTP_TTL_MINUTES)`.
 */
export function addMinutes(minutes: number, from: Date = nowUtc()): Date {
  return dayjs.utc(from).add(minutes, 'minute').toDate();
}

/**
 * Returns a UTC Date N hours from now (or from a given base date).
 */
export function addHours(hours: number, from: Date = nowUtc()): Date {
  return dayjs.utc(from).add(hours, 'hour').toDate();
}

/**
 * Returns a UTC Date N days from now (or from a given base date).
 * Use for refresh-token expiry: `addDays(REFRESH_TOKEN_TTL_DAYS)`.
 */
export function addDays(days: number, from: Date = nowUtc()): Date {
  return dayjs.utc(from).add(days, 'day').toDate();
}

/**
 * Returns a UTC Date N days in the past from now (or from a given base date).
 * Use for log-retention cutoff: `subtractDays(LOG_RETENTION_DAYS)`.
 */
export function subtractDays(days: number, from: Date = nowUtc()): Date {
  return dayjs.utc(from).subtract(days, 'day').toDate();
}

// ─── Expiry checks ────────────────────────────────────────────────────────────

/** Returns true if the given date is in the past. Null is treated as already expired. */
export function isExpired(expiresAt: Date | null | undefined): boolean {
  if (!expiresAt) return true;
  return dayjs.utc().isAfter(dayjs.utc(expiresAt));
}

/** Returns the number of seconds remaining until expiry (negative if already expired). */
export function secondsUntilExpiry(expiresAt: Date): number {
  return dayjs.utc(expiresAt).diff(dayjs.utc(), 'second');
}

/** Returns the number of minutes remaining until expiry (negative if already expired). */
export function minutesUntilExpiry(expiresAt: Date): number {
  return dayjs.utc(expiresAt).diff(dayjs.utc(), 'minute');
}

// ─── Date range parsing ───────────────────────────────────────────────────────

/**
 * Parses a date string for use as the START of a filter range.
 *
 * - If the string contains timezone info (ISO 8601 with offset or Z), it is
 *   parsed as-is and converted to UTC.
 * - If it is a bare date ("2025-01-15"), it is interpreted as midnight at the
 *   START of that day in Myanmar local time, then converted to UTC.
 *
 * Use with TypeORM: `Between(parseRangeStart(dto.startDate), parseRangeEnd(dto.endDate))`
 */
export function parseRangeStart(dateStr: string): Date {
  if (hasTimezoneInfo(dateStr)) {
    return dayjs(dateStr).utc().toDate();
  }
  return dayjs
    .tz(dateStr + 'T00:00:00', MYANMAR_TZ)
    .utc()
    .toDate();
}

/**
 * Parses a date string for use as the END of a filter range.
 *
 * - If the string contains timezone info, it is parsed as-is and converted to UTC.
 * - If it is a bare date ("2025-01-15"), it is interpreted as 23:59:59.999 at the
 *   END of that day in Myanmar local time, then converted to UTC.
 */
export function parseRangeEnd(dateStr: string): Date {
  if (hasTimezoneInfo(dateStr)) {
    return dayjs(dateStr).utc().toDate();
  }
  return dayjs
    .tz(dateStr + 'T23:59:59.999', MYANMAR_TZ)
    .utc()
    .toDate();
}

// ─── Formatting / display ─────────────────────────────────────────────────────

/**
 * Converts a UTC Date to a formatted string in Myanmar local time.
 * Default format: "YYYY-MM-DD HH:mm:ss"
 */
export function toMyanmarDisplay(
  date: Date,
  format = 'YYYY-MM-DD HH:mm:ss',
): string {
  return dayjs.utc(date).tz(MYANMAR_TZ).format(format);
}

/**
 * Converts a UTC Date to Myanmar local time and returns a dayjs instance
 * for further chaining.
 */
export function toMyanmarTime(date: Date): dayjs.Dayjs {
  return dayjs.utc(date).tz(MYANMAR_TZ);
}

/**
 * Formats a Date as an ISO 8601 string with Myanmar offset (+06:30).
 * Useful when the API response must convey the local time to clients.
 */
export function toMyanmarIso(date: Date): string {
  return dayjs.utc(date).tz(MYANMAR_TZ).format();
}

// ─── Date arithmetic utilities ────────────────────────────────────────────────

/**
 * Returns the start of a given day (00:00:00.000) in Myanmar local time,
 * expressed as a UTC Date. Useful for "today's records" queries.
 */
export function startOfDayMyanmar(date: Date = nowUtc()): Date {
  return dayjs.utc(date).tz(MYANMAR_TZ).startOf('day').utc().toDate();
}

/**
 * Returns the end of a given day (23:59:59.999) in Myanmar local time,
 * expressed as a UTC Date.
 */
export function endOfDayMyanmar(date: Date = nowUtc()): Date {
  return dayjs.utc(date).tz(MYANMAR_TZ).endOf('day').utc().toDate();
}

/**
 * Returns [startOfDay, endOfDay] in UTC for a given date in Myanmar time.
 * Convenience wrapper for building a single-day filter range.
 */
export function dayRangeMyanmar(date: Date = nowUtc()): [Date, Date] {
  return [startOfDayMyanmar(date), endOfDayMyanmar(date)];
}

/**
 * Returns true if the given UTC date falls within today in Myanmar local time.
 */
export function isTodayMyanmar(date: Date): boolean {
  const myanmarDate = dayjs.utc(date).tz(MYANMAR_TZ);
  const myanmarNow = dayjs.utc().tz(MYANMAR_TZ);
  return myanmarDate.isSame(myanmarNow, 'day');
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function hasTimezoneInfo(dateStr: string): boolean {
  return (
    dateStr.includes('T') ||
    dateStr.endsWith('Z') ||
    /[+-]\d{2}:\d{2}$/.test(dateStr)
  );
}
