/**
 * Hash and signature primitives (spec §3.3).
 *
 * D(kind,x) = lowercase_hex(SHA256(UTF8("LAGI-BEDROCK/" + kind + "/1\n") || J(x)))
 * S(kind,x) = UTF8("LAGI-BEDROCK/sign/" + kind + "/1\n" + D(kind,x))
 * Ed25519 signs S, including the ASCII hex digest.
 */
import {
  createHash,
  sign as nodeSign,
  verify as nodeVerify,
  createPrivateKey,
  createPublicKey,
  createCipheriv,
  createDecipheriv,
  getRandomValues,
} from "node:crypto";
import { BedrockError } from "./errors.js";
import { J, type Json } from "./canon.js";

export const HASH_KINDS = ["manifest", "charter", "pin", "input", "audit", "checkpoint"] as const;
export type HashKind = (typeof HASH_KINDS)[number];

export function sha256Hex(b: Uint8Array): string {
  return createHash("sha256").update(b).digest("hex");
}

export function sha256(b: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(b).digest());
}

export function D(kind: HashKind, x: unknown): string {
  if (!HASH_KINDS.includes(kind)) throw new BedrockError("SCHEMA", `unknown hash kind ${kind}`);
  const prefix = new TextEncoder().encode(`LAGI-BEDROCK/${kind}/1\n`);
  const body = J(x);
  const h = createHash("sha256");
  h.update(prefix);
  h.update(body);
  return h.digest("hex");
}

export function S(kind: HashKind, x: unknown): Uint8Array {
  return new TextEncoder().encode(`LAGI-BEDROCK/sign/${kind}/1\n${D(kind, x)}`);
}

// ---------------------------------------------------------------------------
// base64url (canonical, unpadded)
// ---------------------------------------------------------------------------

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

export function b64urlEncode(b: Uint8Array): string {
  return Buffer.from(b).toString("base64url");
}

/** Decode canonical unpadded base64url; rejects padding and re-encode mismatches. */
export function b64urlDecode(s: string): Uint8Array {
  if (!B64URL_RE.test(s)) throw new BedrockError("PARSE", "invalid base64url");
  const b = new Uint8Array(Buffer.from(s, "base64url"));
  if (b64urlEncode(b) !== s) throw new BedrockError("PARSE", "noncanonical base64url");
  return b;
}

const HEX_RE = /^[0-9a-f]{64}$/;

export function isHash(s: unknown): s is string {
  return typeof s === "string" && HEX_RE.test(s);
}

export function hexDecode(s: string): Uint8Array {
  if (!/^[0-9a-f]+$/.test(s) || s.length % 2 !== 0) {
    throw new BedrockError("PARSE", "invalid lowercase hex");
  }
  return new Uint8Array(Buffer.from(s, "hex"));
}

// ---------------------------------------------------------------------------
// Ed25519 with strict canonicality checks (spec §3.3):
//  - reject noncanonical encodings, S >= L, small-order public keys / R points
// ---------------------------------------------------------------------------

const ED_P = (1n << 255n) - 19n;
const ED_L = (1n << 252n) + 27742317777372353535851937790883648493n;
const ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;
const ED_SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752n;

function fe(x: bigint): bigint {
  const r = x % ED_P;
  return r >= 0n ? r : r + ED_P;
}

function fePow(base: bigint, e: bigint): bigint {
  let r = 1n;
  let b = fe(base);
  while (e > 0n) {
    if (e & 1n) r = fe(r * b);
    b = fe(b * b);
    e >>= 1n;
  }
  return r;
}

interface Point {
  x: bigint;
  y: bigint;
}

const IDENTITY: Point = { x: 0n, y: 1n };

function edAdd(P: Point, Q: Point): Point {
  // a = -1 twisted Edwards addition.
  const x1x2 = fe(P.x * Q.x);
  const y1y2 = fe(P.y * Q.y);
  const dx1x2y1y2 = fe(ED_D * x1x2 * y1y2);
  const xNum = fe(P.x * Q.y + P.y * Q.x);
  const yNum = fe(y1y2 + x1x2);
  const xDen = fe(1n + dx1x2y1y2);
  const yDen = fe(1n - dx1x2y1y2);
  return { x: fe(xNum * fePow(xDen, ED_P - 2n)), y: fe(yNum * fePow(yDen, ED_P - 2n)) };
}

function edDouble(P: Point): Point {
  return edAdd(P, P);
}

/**
 * Decode a canonical Ed25519 point encoding. Returns null when the encoding is
 * noncanonical (y >= p) or the point is not on the curve.
 */
export function decodePoint(enc: Uint8Array): Point | null {
  if (enc.length !== 32) return null;
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(enc[i]!);
  const xSign = (y >> 255n) & 1n;
  y &= (1n << 255n) - 1n;
  if (y >= ED_P) return null; // noncanonical
  // x^2 = (y^2 - 1) / (d y^2 + 1)
  const yy = fe(y * y);
  const num = fe(yy - 1n);
  const den = fe(ED_D * yy + 1n);
  let x = fePow(fe(num * fePow(den, ED_P - 2n)), (ED_P + 3n) >> 3n);
  if (fe(x * x) !== fe(num * fePow(den, ED_P - 2n))) {
    x = fe(x * ED_SQRT_M1);
    if (fe(x * x) !== fe(num * fePow(den, ED_P - 2n))) return null; // not on curve
  }
  if ((x & 1n) !== xSign) x = fe(ED_P - x);
  if (x === 0n && xSign === 1n) return null; // negative zero x encoding
  return { x, y };
}

/** True when the point lies in the small (order-8) subgroup. */
export function isSmallOrder(P: Point): boolean {
  let Q = edDouble(P);
  Q = edDouble(Q);
  Q = edDouble(Q); // Q = [8]P
  return Q.x === 0n && Q.y === 1n;
}

/** Canonical, on-curve, not small order. */
export function isAcceptablePoint(enc: Uint8Array): boolean {
  const p = decodePoint(enc);
  return p !== null && !isSmallOrder(p);
}

export function isAcceptablePublicKey(enc: Uint8Array): boolean {
  return isAcceptablePoint(enc);
}

function scalarFromBytesLE(b: Uint8Array): bigint {
  let s = 0n;
  for (let i = b.length - 1; i >= 0; i--) s = (s << 8n) | BigInt(b[i]!);
  return s;
}

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function privateKeyFromSeed(seed: Uint8Array) {
  if (seed.length !== 32) throw new BedrockError("SCHEMA", "ed25519 seed must be 32 bytes");
  return createPrivateKey({
    key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]),
    format: "der",
    type: "pkcs8",
  });
}

function publicKeyFromBytes(pub: Uint8Array) {
  return createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(pub)]),
    format: "der",
    type: "spki",
  });
}

export function ed25519PublicKey(seed: Uint8Array): Uint8Array {
  const pub = createPublicKey(privateKeyFromSeed(seed)).export({ format: "der", type: "spki" });
  return new Uint8Array(pub.subarray(pub.length - 32));
}

export function ed25519Sign(seed: Uint8Array, msg: Uint8Array): Uint8Array {
  return new Uint8Array(nodeSign(null, Buffer.from(msg), privateKeyFromSeed(seed)));
}

/**
 * Strict Ed25519 verify. Checks encoding canonicality, S < L, on-curve and
 * non-small-order R and A before handing to the RFC 8032 verifier.
 * Returns boolean — callers map failure to SIGNATURE_INVALID.
 */
export function ed25519Verify(pub: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean {
  if (pub.length !== 32 || sig.length !== 64) return false;
  const R = sig.subarray(0, 32);
  const Sb = sig.subarray(32, 64);
  if (scalarFromBytesLE(Sb) >= ED_L) return false;
  if (!isAcceptablePoint(R)) return false;
  if (!isAcceptablePoint(pub)) return false;
  try {
    return nodeVerify(null, Buffer.from(msg), publicKeyFromBytes(pub), Buffer.from(sig));
  } catch {
    return false;
  }
}

/** sign(kind, body, key_id, key_handle) per spec §8.2 — returns Detached. */
export function signObject(
  kind: HashKind,
  body: Json,
  keyId: string,
  seed: Uint8Array,
): { key_id: string; signature: string } {
  return { key_id: keyId, signature: b64urlEncode(ed25519Sign(seed, S(kind, body))) };
}

export function verifyObject(
  kind: HashKind,
  body: Json,
  publicKeyHex: string,
  signatureB64: string,
): boolean {
  let sig: Uint8Array;
  let pub: Uint8Array;
  try {
    sig = b64urlDecode(signatureB64);
    pub = hexDecode(publicKeyHex);
  } catch {
    return false;
  }
  if (sig.length !== 64 || pub.length !== 32) return false;
  return ed25519Verify(pub, sig, S(kind, body));
}

// ---------------------------------------------------------------------------
// AES-256-GCM response/output envelope (spec §10.1)
// ---------------------------------------------------------------------------

export interface EncEnvelope {
  version: 1;
  key_id: string;
  nonce_base64url: string;
  ciphertext_base64url: string;
}

export function aesGcmEncrypt(
  key: Uint8Array,
  keyId: string,
  aad: Uint8Array,
  plaintext: Uint8Array,
): EncEnvelope {
  const nonce = new Uint8Array(12);
  getRandomValues(nonce);
  const c = createCipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  const tag = c.getAuthTag();
  return {
    version: 1,
    key_id: keyId,
    nonce_base64url: b64urlEncode(nonce),
    ciphertext_base64url: b64urlEncode(new Uint8Array(Buffer.concat([ct, tag]))),
  };
}

export function aesGcmDecrypt(
  keys: Map<string, Uint8Array>,
  aad: Uint8Array,
  env: EncEnvelope,
): Uint8Array | null {
  const key = keys.get(env.key_id);
  if (!key) return null;
  try {
    const nonce = b64urlDecode(env.nonce_base64url);
    const ctTag = b64urlDecode(env.ciphertext_base64url);
    const d = createDecipheriv("aes-256-gcm", Buffer.from(key), Buffer.from(nonce));
    d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(ctTag.subarray(ctTag.length - 16)));
    return new Uint8Array(Buffer.concat([d.update(Buffer.from(ctTag.subarray(0, ctTag.length - 16))), d.final()]));
  } catch {
    return null;
  }
}
