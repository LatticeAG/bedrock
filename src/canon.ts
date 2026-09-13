/**
 * RFC 8785 (JCS) canonicalization over Bedrock's restricted JSON domain:
 * integers only (no fractional/exponent tokens), NFC strings, closed objects.
 * Object member order uses UTF-16 code-unit ordering (spec §3.2).
 */
import { BedrockError } from "./errors.js";

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

export const MAX_DEPTH = 16;
export const MAX_MEMBERS = 1024;

/** Number of UTF-16 code units, i.e. JS string length already counts code units. */
function utf16KeyCompare(a: string, b: string): number {
  // JS string comparison is by UTF-16 code units — exactly RFC 8785 ordering.
  return a < b ? -1 : a > b ? 1 : 0;
}

export function canonicalString(v: unknown): string {
  return canonicalInto(v as Json, 0);
}

function canonicalInto(v: Json, depth: number): string {
  if (depth > MAX_DEPTH) throw new BedrockError("LIMIT", "nesting depth > 16");
  if (v === null) return "null";
  switch (typeof v) {
    case "boolean":
      return v ? "true" : "false";
    case "number":
      return numberToJcs(v);
    case "string":
      return stringToJcs(v);
    case "object": {
      if (Array.isArray(v)) {
        return "[" + v.map((e) => canonicalInto(e, depth + 1)).join(",") + "]";
      }
      const keys = Object.keys(v).sort(utf16KeyCompare);
      if (keys.length > MAX_MEMBERS) {
        throw new BedrockError("LIMIT", "object member count > 1024");
      }
      return (
        "{" +
        keys
          .map((k) => stringToJcs(k) + ":" + canonicalInto((v as Record<string, Json>)[k]!, depth + 1))
          .join(",") +
        "}"
      );
    }
    default:
      throw new BedrockError("SCHEMA", "unsupported JSON value");
  }
}

function numberToJcs(n: number): string {
  if (!Number.isInteger(n)) {
    throw new BedrockError("SCHEMA", "non-integer numbers are outside the Bedrock domain");
  }
  if (Math.abs(n) > Number.MAX_SAFE_INTEGER) {
    throw new BedrockError("SCHEMA", "integer outside safe range");
  }
  if (Object.is(n, -0)) throw new BedrockError("SCHEMA", "negative zero rejected");
  return String(n);
}

function stringToJcs(s: string): string {
  let out = '"';
  for (const ch of s) {
    const o = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\r") out += "\\r";
    else if (o < 0x20) out += "\\u" + o.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** J(x): canonical UTF-8 bytes of x. */
export function J(x: unknown): Uint8Array {
  return new TextEncoder().encode(canonicalString(x));
}

// ---------------------------------------------------------------------------
// Strict JSON parsing (spec §3.2): UTF-8, no BOM, no duplicate keys, no lone
// surrogates, integer-only numeric tokens, depth/member bounds, NFC strings.
// ---------------------------------------------------------------------------

export function parseJsonBytes(bytes: Uint8Array): Json {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw new BedrockError("PARSE", "UTF-8 BOM not allowed");
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new BedrockError("PARSE", "invalid UTF-8");
  }
  return parseJson(text);
}

export function parseJson(text: string): Json {
  const p = new JsonParser(text);
  const v = p.value(0);
  p.skipWs();
  if (!p.eof()) throw new BedrockError("PARSE", "trailing bytes after JSON value");
  return v;
}

class JsonParser {
  i = 0;
  constructor(readonly s: string) {}
  eof(): boolean {
    return this.i >= this.s.length;
  }
  skipWs(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }
  peek(): number {
    return this.i < this.s.length ? this.s.charCodeAt(this.i) : -1;
  }
  fail(msg: string): never {
    throw new BedrockError("PARSE", msg);
  }
  value(depth: number): Json {
    if (depth > MAX_DEPTH) this.fail("nesting depth > 16");
    this.skipWs();
    const c = this.peek();
    if (c === 0x7b) return this.object(depth);
    if (c === 0x5b) return this.array(depth);
    if (c === 0x22) return this.string();
    if (c === 0x74) return this.lit("true", true);
    if (c === 0x66) return this.lit("false", false);
    if (c === 0x6e) return this.lit("null", null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return this.number();
    this.fail("unexpected token");
  }
  lit(word: string, v: Json): Json {
    if (!this.s.startsWith(word, this.i)) this.fail("bad literal");
    this.i += word.length;
    return v;
  }
  number(): number {
    const start = this.i;
    if (this.peek() === 0x2d) this.i++;
    // integer part: 0 | [1-9][0-9]*
    if (this.peek() === 0x30) {
      this.i++;
    } else if (this.peek() >= 0x31 && this.peek() <= 0x39) {
      while (this.peek() >= 0x30 && this.peek() <= 0x39) this.i++;
    } else {
      this.fail("bad number");
    }
    const c = this.peek();
    // Bedrock rejects decimal point, exponent, leading plus, negative zero.
    if (c === 0x2e || c === 0x65 || c === 0x45 || c === 0x2b) {
      this.fail("non-integer numeric token");
    }
    const raw = this.s.slice(start, this.i);
    if (raw === "-0") this.fail("negative zero rejected");
    const n = Number(raw);
    if (!Number.isSafeInteger(n)) this.fail("integer outside safe range");
    return n;
  }
  string(): string {
    // opening quote already peeked
    this.i++;
    let out = "";
    for (;;) {
      if (this.eof()) this.fail("unterminated string");
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        break;
      }
      if (c === 0x5c) {
        this.i++;
        const e = this.s.charCodeAt(this.i);
        this.i++;
        switch (e) {
          case 0x22: out += '"'; break;
          case 0x5c: out += "\\"; break;
          case 0x2f: out += "/"; break;
          case 0x62: out += "\b"; break;
          case 0x66: out += "\f"; break;
          case 0x6e: out += "\n"; break;
          case 0x72: out += "\r"; break;
          case 0x74: out += "\t"; break;
          case 0x75: {
            const h1 = this.s.slice(this.i, this.i + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(h1)) this.fail("bad \\u escape");
            this.i += 4;
            const u1 = parseInt(h1, 16);
            if (u1 >= 0xd800 && u1 <= 0xdbff) {
              // high surrogate must be followed by \uDC00-\uDFFF
              if (this.s.charCodeAt(this.i) !== 0x5c || this.s.charCodeAt(this.i + 1) !== 0x75) {
                this.fail("lone surrogate");
              }
              const h2 = this.s.slice(this.i + 2, this.i + 6);
              if (!/^[0-9a-fA-F]{4}$/.test(h2)) this.fail("bad \\u escape");
              const u2 = parseInt(h2, 16);
              if (u2 < 0xdc00 || u2 > 0xdfff) this.fail("lone surrogate");
              this.i += 6;
              out += String.fromCharCode(u1, u2);
            } else if (u1 >= 0xdc00 && u1 <= 0xdfff) {
              this.fail("lone surrogate");
            } else {
              out += String.fromCharCode(u1);
            }
            break;
          }
          default:
            this.fail("bad escape");
        }
        continue;
      }
      if (c < 0x20) this.fail("unescaped control character");
      if (c >= 0xd800 && c <= 0xdfff) this.fail("lone surrogate");
      out += this.s[this.i];
      this.i++;
    }
    if (out !== out.normalize("NFC")) this.fail("string is not NFC");
    return out;
  }
  object(depth: number): Json {
    this.i++; // {
    const obj: Record<string, Json> = {};
    let count = 0;
    this.skipWs();
    if (this.peek() === 0x7d) {
      this.i++;
      return obj;
    }
    for (;;) {
      this.skipWs();
      if (this.peek() !== 0x22) this.fail("object key must be a string");
      const key = this.string();
      if (Object.prototype.hasOwnProperty.call(obj, key)) {
        this.fail("duplicate object member");
      }
      this.skipWs();
      if (this.peek() !== 0x3a) this.fail("expected ':'");
      this.i++;
      obj[key] = this.value(depth + 1);
      count++;
      if (count > MAX_MEMBERS) this.fail("object member count > 1024");
      this.skipWs();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x7d) {
        this.i++;
        break;
      }
      this.fail("expected ',' or '}'");
    }
    return obj;
  }
  array(depth: number): Json {
    this.i++; // [
    const arr: Json[] = [];
    this.skipWs();
    if (this.peek() === 0x5d) {
      this.i++;
      return arr;
    }
    for (;;) {
      arr.push(this.value(depth + 1));
      this.skipWs();
      const c = this.peek();
      if (c === 0x2c) {
        this.i++;
        continue;
      }
      if (c === 0x5d) {
        this.i++;
        break;
      }
      this.fail("expected ',' or ']'");
    }
    return arr;
  }
}

/** Structural JSON sanity for outputs: finite RFC8785-compatible, NFC, depth/bounds. */
export function assertCanonicalJson(v: unknown, maxBytes: number): void {
  const s = canonicalString(v); // throws on bad types/depth/members
  if (new TextEncoder().encode(s).length > maxBytes) {
    throw new BedrockError("LIMIT", "canonical bytes bound exceeded");
  }
}

/** Object member names sorted in UTF-16 code-unit order (conformance op). */
export function canonicalKeyOrder(obj: Record<string, Json>): string[] {
  return Object.keys(obj).sort(utf16KeyCompare);
}
