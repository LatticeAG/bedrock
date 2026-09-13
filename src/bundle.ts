/**
 * Bundle, chain, and signed-pin-update verification (spec §5.2).
 */
import { BedrockError } from "./errors.js";
import { canonicalString } from "./canon.js";
import { D, verifyObject } from "./crypto.js";
import type { Authority, Bundle, Charter, Detached, Pin, RootFile, SignedPinUpdate } from "./types.js";
import { vBundle, vCharter, vManifest, vSignedPinUpdate } from "./schema.js";
import { checkBundleSemantics, checkLineage, manifestDigestOrThrow, pinOf } from "./compiler.js";

function fail(code: ConstructorParameters<typeof BedrockError>[0], msg: string): never {
  throw new BedrockError(code, msg);
}

/** Check one Detached set against an authority. Enforces §3.3 ordering rules. */
export function checkSignatures(
  body: unknown,
  kind: "charter" | "pin",
  signatures: Detached[],
  authority: Authority,
): { signatures: number; required: number } {
  const eligible = new Map(authority.keys.map((k) => [k.key_id, k.public_key]));
  // duplicate signature IDs first (SIGNATURE_DUPLICATE before set-order check)
  const ids = signatures.map((s) => s.key_id);
  if (new Set(ids).size !== ids.length) fail("SIGNATURE_DUPLICATE", "duplicate key_id in signatures");
  for (let i = 1; i < ids.length; i++) {
    if (ids[i - 1]! >= ids[i]!) fail("SCHEMA", "signature entries not sorted by key_id");
  }
  // unknown eligible-key lookup before quorum counting
  for (const s of signatures) {
    if (!eligible.has(s.key_id)) fail("KEY_UNKNOWN", `key ${s.key_id} not eligible`);
  }
  for (const s of signatures) {
    const pub = eligible.get(s.key_id)!;
    if (!verifyObject(kind, body as never, pub, s.signature)) {
      fail("SIGNATURE_INVALID", `signature by ${s.key_id} invalid`);
    }
  }
  if (signatures.length < authority.threshold) fail("QUORUM", "below threshold");
  return { signatures: signatures.length, required: authority.threshold };
}

export interface BundleVerification {
  valid: true;
  pin: Pin;
  signatures: number;
  required: number;
}

/**
 * verifyBundle(bundle, root, predecessors): full chain verification.
 * Genesis is verified against root.bootstrap; each successor under its
 * predecessor's next_authority. `predecessors` are complete bundles in
 * ascending version order.
 */
export function verifyBundle(
  bundle: Bundle,
  root: RootFile,
  predecessors: Bundle[],
): BundleVerification {
  const b = vBundle(bundle);
  vCharter(b.charter);
  vManifest(b.manifest);
  const manifestHash = manifestDigestOrThrow(b.charter, b.manifest);

  // Determine which authority must sign this version by walking the chain.
  const chain = [...predecessors].sort((a, b) => a.charter.version - b.charter.version);
  let authority: Authority;
  if (b.charter.version === 1) {
    if (chain.length !== 0) fail("SCHEMA", "genesis bundle with predecessors");
    if (b.charter.previous_hash !== null) fail("SCHEMA", "genesis previous_hash must be null");
    authority = root.bootstrap;
  } else {
    if (chain.length !== b.charter.version - 1) {
      fail("HASH_MISMATCH", "incomplete predecessor chain");
    }
    // verify the whole predecessor chain first
    let prev: Bundle | null = null;
    for (const p of chain) {
      verifySingle(p, root, prev);
      prev = p;
    }
    const pred = chain[chain.length - 1]!;
    if (pred.charter.version !== b.charter.version - 1) fail("VERSION_CONFLICT", "version gap");
    const predHash = D("charter", pred.charter);
    if (b.charter.previous_hash !== predHash) {
      fail("HASH_MISMATCH", "previous_hash does not name predecessor charter hash");
    }
    authority = pred.charter.next_authority;
  }

  const { signatures, required } = checkSignatures(b.charter, "charter", b.signatures, authority);
  checkBundleSemantics(b.charter, b.manifest);
  checkLineage(b.charter, b.manifest, root);
  return { valid: true, pin: pinOf(b.charter, manifestHash), signatures, required };
}

/** Verify one bundle's own structural/signature validity against a known predecessor. */
function verifySingle(bundle: Bundle, root: RootFile, predecessor: Bundle | null): void {
  const b = vBundle(bundle);
  vCharter(b.charter);
  vManifest(b.manifest);
  manifestDigestOrThrow(b.charter, b.manifest);
  let authority: Authority;
  if (predecessor === null) {
    if (b.charter.version !== 1 || b.charter.previous_hash !== null) {
      fail("SCHEMA", "bad genesis");
    }
    authority = root.bootstrap;
  } else {
    if (b.charter.version !== predecessor.charter.version + 1) {
      fail("VERSION_CONFLICT", "version must be predecessor + 1");
    }
    if (b.charter.previous_hash !== D("charter", predecessor.charter)) {
      fail("HASH_MISMATCH", "previous_hash mismatch");
    }
    authority = predecessor.charter.next_authority;
  }
  checkSignatures(b.charter, "charter", b.signatures, authority);
  checkBundleSemantics(b.charter, b.manifest);
  checkLineage(b.charter, b.manifest, root);
}

/**
 * Structural + signature verification of a SignedPinUpdate under `authority`.
 * CAS/expiry/head checks belong to the serving deployment (see tenant.ts).
 */
export function verifyPinUpdateSignatures(
  update: SignedPinUpdate,
  authority: Authority,
  tenantId: string,
  gatewayId: string,
): void {
  const u = vSignedPinUpdate(update);
  // foreign update fails SCHEMA before signatures are read
  if (u.update.tenant_id !== tenantId || u.update.gateway_id !== gatewayId) {
    fail("SCHEMA", "pin update tenant/gateway mismatch");
  }
  checkSignatures(u.update, "pin", u.signatures, authority);
}

export function canonicalEqual(a: unknown, b: unknown): boolean {
  return canonicalString(a as never) === canonicalString(b as never);
}
