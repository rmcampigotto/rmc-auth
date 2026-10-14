const UNIT_TO_SECONDS: Record<string, number> = {
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hr: 3600,
  hrs: 3600,
  hour: 3600,
  hours: 3600,
  d: 86400,
  day: 86400,
  days: 86400,
  w: 604800,
  week: 604800,
  weeks: 604800,
};

/**
 * Converts a JWT-style duration (`3600`, `'3600'`, `'15m'`, `'1 hour'`, `'7d'`, `'2w'`) to seconds.
 * @throws Error if the value cannot be parsed or is not positive.
 */
export function parseDurationToSeconds(value: string | number): number {
  if (typeof value === "number") {
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error(`Invalid duration: ${value}`);
    }
    return Math.floor(value);
  }
  if (typeof value !== "string") {
    throw new Error(`Invalid duration: ${String(value)}`);
  }
  const trimmed = value.trim().toLowerCase();
  if (/^\d+$/.test(trimmed)) {
    const n = parseInt(trimmed, 10);
    if (n <= 0) throw new Error(`Invalid duration: ${value}`);
    return n;
  }
  const match = trimmed.match(/^(\d+(?:\.\d+)?)\s*([a-z]+)$/);
  if (!match || !(match[2] in UNIT_TO_SECONDS)) {
    throw new Error(`Invalid duration: '${value}'. Use seconds or a string like '15m', '1h', '7d'.`);
  }
  const seconds = Math.floor(parseFloat(match[1]) * UNIT_TO_SECONDS[match[2]]);
  if (seconds <= 0) throw new Error(`Invalid duration: ${value}`);
  return seconds;
}
