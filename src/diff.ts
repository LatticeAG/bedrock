/**
 * Semantic diff (spec §8.1): compares two canonical objects; paths are RFC6901
 * JSON pointers sorted bytewise; additions/deletions use null for the absent
 * side; any array difference reports the whole array member.
 */
import { canonicalString, type Json } from "./canon.js";

export interface Change {
  path: string;
  before: Json;
  after: Json;
}

function escapePointer(seg: string): string {
  return seg.replace(/~/g, "~0").replace(/\//g, "~1");
}

function walk(prefix: string, before: Json, after: Json, out: Change[]): void {
  if (canonicalString(before) === canonicalString(after)) return;
  const bObj = isPlain(before);
  const aObj = isPlain(after);
  if (bObj && aObj) {
    const keys = new Set([...Object.keys(before as object), ...Object.keys(after as object)]);
    for (const k of [...keys].sort()) {
      const p = prefix + "/" + escapePointer(k);
      const b = (before as Record<string, Json>)[k];
      const a = (after as Record<string, Json>)[k];
      const bHas = Object.prototype.hasOwnProperty.call(before, k);
      const aHas = Object.prototype.hasOwnProperty.call(after, k);
      walk(p, bHas ? b! : null, aHas ? a! : null, out);
    }
    return;
  }
  // array differences report the whole array
  out.push({ path: prefix, before, after });
}

function isPlain(v: Json): boolean {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function semanticDiff(before: Json, after: Json): Change[] {
  const out: Change[] = [];
  walk("", before, after, out);
  return out.sort((x, y) => (x.path < y.path ? -1 : x.path > y.path ? 1 : 0));
}
