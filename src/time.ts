/** Bedrock Time: exactly YYYY-MM-DDTHH:mm:ss.sssZ, valid Gregorian date. */
import { BedrockError } from "./errors.js";

const TIME_RE =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$/;

export function isTime(s: string): boolean {
  const m = TIME_RE.exec(s);
  if (!m) return false;
  const [, Y, M, D, h, mi, sec, ms] = m;
  const year = +Y!, month = +M!, day = +D!, hour = +h!, minute = +mi!, second = +sec!, millis = +ms!;
  if (month < 1 || month > 12) return false;
  if (hour > 23 || minute > 59 || second > 59) return false; // no leap seconds
  const dim = daysInMonth(year, month);
  if (day < 1 || day > dim) return false;
  return true;
}

function daysInMonth(y: number, m: number): number {
  switch (m) {
    case 1: case 3: case 5: case 7: case 8: case 10: case 12: return 31;
    case 4: case 6: case 9: case 11: return 30;
    case 2:
      return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0 ? 29 : 28;
    default: return 0;
  }
}

export function parseTime(s: string): number {
  if (!isTime(s)) throw new BedrockError("SCHEMA", `invalid Time: ${JSON.stringify(s)}`);
  // Date.parse is safe here because the grammar has already been validated.
  return Date.parse(s);
}

export function formatTime(ms: number): string {
  return new Date(ms).toISOString();
}
