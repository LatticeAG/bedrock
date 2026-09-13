/** Bedrock ID grammar: ^PREFIX_[A-Za-z0-9_-]{21}$ with locked nanoid alphabet. */
import { getRandomValues } from "node:crypto";
import { BedrockError } from "./errors.js";

export const ID_ALPHABET =
  "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-";
export const ID_SUFFIX_LEN = 21;

export const PREFIXES = [
  "bte", "bch", "bgw", "bin", "bpr", "bky", "brq", "brl", "bds", "blg",
] as const;
export type Prefix = (typeof PREFIXES)[number];

const ID_RE = new RegExp(
  `^(${PREFIXES.join("|")})_[A-Za-z0-9_-]{${ID_SUFFIX_LEN}}$`,
);

export function isBedrockId(s: string): boolean {
  return ID_RE.test(s);
}

export function hasPrefix(s: string, p: Prefix): boolean {
  return s.startsWith(p + "_") && isBedrockId(s);
}

/** nanoid with the locked 64-char alphabet, 21 chars. */
export function nanoidSuffix(rand: (n: number) => Uint8Array = defaultRand): string {
  const bytes = rand(ID_SUFFIX_LEN);
  let out = "";
  for (let i = 0; i < ID_SUFFIX_LEN; i++) out += ID_ALPHABET[bytes[i]! & 63];
  return out;
}

function defaultRand(n: number): Uint8Array {
  const b = new Uint8Array(n);
  getRandomValues(b);
  return b;
}

export function newId(prefix: Prefix): string {
  return `${prefix}_${nanoidSuffix()}`;
}

/** Test helper: prefix + 21 copies of a single char, e.g. ID("bte","A"). */
export function fixedId(prefix: Prefix, c: string): string {
  if (c.length !== 1 || !ID_ALPHABET.includes(c)) {
    throw new BedrockError("SCHEMA", "bad fixture id char");
  }
  return `${prefix}_${c.repeat(ID_SUFFIX_LEN)}`;
}
