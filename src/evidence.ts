/**
 * Offline evidence verification (spec §4.4, §8.2, §13.2).
 * Validates supplied root equality to the caller-pinned root, entry
 * schema/seq/hash/signature, predecessor linkage, bundle authority, and the
 * final checkpoint — in that order. Never contacts the registry; never
 * dispatches on replay.
 */
import { canonicalString, type Json } from "./canon.js";
import { D, hexDecode, ed25519Verify, S, b64urlDecode } from "./crypto.js";
import type {
  AuditEntry, Bundle, Charter, Checkpoint, Decision, Evidence, Pin,
  RootFile, SignedPinUpdate, Verification,
} from "./types.js";
import { vEvidence, vAuditEntry, vCheckpoint, vPinUpdate } from "./schema.js";
import { evaluate } from "./evaluator.js";
import { canonicalEqual, verifyBundle } from "./bundle.js";

const ZERO_HASH = "0".repeat(64);

interface Fail {
  integrity: "INVALID" | "INCOMPLETE";
  throughSeq: number;
}

function auditKeyAt(root: RootFile, seq: number): { key_id: string; public_key: string } | null {
  return (
    root.audit_keys.find(
      (k) => k.from_seq <= seq && (k.through_seq === null || seq <= k.through_seq),
    ) ?? null
  );
}

function entryValid(entry: AuditEntry, root: RootFile): boolean {
  try {
    vAuditEntry(entry);
  } catch {
    return false;
  }
  const key = auditKeyAt(root, entry.body.seq);
  if (!key || key.key_id !== entry.key_id) return false;
  if (D("audit", entry.body as unknown as Json) !== entry.hash) return false;
  try {
    return ed25519Verify(
      hexDecode(key.public_key), b64urlDecode(entry.signature),
      S("audit", entry.body as unknown as Json),
    );
  } catch {
    return false;
  }
}

function checkpointValid(cp: Checkpoint, root: RootFile): boolean {
  try {
    vCheckpoint(cp);
  } catch {
    return false;
  }
  const key = auditKeyAt(root, cp.body.through_seq + 1) ?? auditKeyAt(root, cp.body.through_seq);
  if (!key || key.key_id !== cp.key_id) return false;
  if (cp.body.tenant_id !== root.tenant_id || cp.body.log_id !== root.log_id) return false;
  try {
    return ed25519Verify(
      hexDecode(key.public_key), b64urlDecode(cp.signature),
      S("checkpoint", cp.body as unknown as Json),
    );
  } catch {
    return false;
  }
}

function pinKey(p: Pin): string {
  return canonicalString(p as unknown as Json);
}

/**
 * verifyEvidence(evidence, root, trustedCheckpoint, replay).
 * `trustedCheckpoint` anchors the verified head; replay re-evaluates decision
 * events against caller-supplied private inputs.
 */
export function verifyEvidence(
  evidence: Evidence,
  root: RootFile,
  trustedCheckpoint: Checkpoint | null,
  replay: boolean,
): Verification {
  let integrity: Verification["integrity"] = "VALID";
  let throughSeq = 0;
  let anchored = false;

  try {
    vEvidence(evidence);
  } catch {
    return { integrity: "INVALID", replay: replay ? "NOT_REQUESTED" : "NOT_REQUESTED", through_seq: 0, anchored: false };
  }

  // 1. supplied root must equal the caller-pinned root
  if (!canonicalEqual(evidence.root, root)) {
    return { integrity: "INVALID", replay: "NOT_REQUESTED", through_seq: 0, anchored: false };
  }

  // 2. bundle authority: bundles must verify as a chain under the root
  const bundles = [...evidence.bundles].sort((a, b) => a.charter.version - b.charter.version);
  const pins = new Map<string, { charter: Charter; manifest: Bundle["manifest"] }>();
  try {
    for (let i = 0; i < bundles.length; i++) {
      verifyBundle(bundles[i]!, root, bundles.slice(0, i));
      const b = bundles[i]!;
      const pin: Pin = {
        charter_id: b.charter.charter_id, version: b.charter.version,
        charter_hash: D("charter", b.charter), manifest_hash: D("manifest", b.manifest),
        engine: b.charter.engine,
      };
      pins.set(pinKey(pin), { charter: b.charter, manifest: b.manifest });
    }
  } catch {
    return { integrity: "INVALID", replay: replay ? "CONTEXT_MISSING" : "NOT_REQUESTED", through_seq: 0, anchored: false };
  }

  // 3. start checkpoint (if present) must verify and name the entry prefix base
  let prevHash = ZERO_HASH;
  let expectSeq = 1;
  if (evidence.start !== null) {
    if (!checkpointValid(evidence.start, root)) {
      return { integrity: "INVALID", replay: replay ? "CONTEXT_MISSING" : "NOT_REQUESTED", through_seq: 0, anchored: false };
    }
    prevHash = evidence.start.body.head_hash;
    expectSeq = evidence.start.body.through_seq + 1;
  }

  // 4. entries: schema → seq → hash → signature → linkage, in order
  const verified: AuditEntry[] = [];
  for (const e of evidence.entries) {
    if (!entryValid(e, root)) {
      integrity = "INVALID";
      break;
    }
    if (e.body.seq !== expectSeq || e.body.prev_hash !== prevHash) {
      integrity = "INVALID";
      break;
    }
    verified.push(e);
    throughSeq = e.body.seq;
    prevHash = e.hash;
    expectSeq = e.body.seq + 1;
  }

  // 5. end checkpoint must be valid and name the verified head
  let endOk = false;
  if (integrity === "VALID") {
    if (!checkpointValid(evidence.end, root)) {
      integrity = "INVALID";
    } else if (
      evidence.end.body.through_seq !== throughSeq ||
      evidence.end.body.head_hash !== prevHash
    ) {
      // bytes absent: supplied evidence does not reach the signed bound
      integrity = "INCOMPLETE";
    } else {
      endOk = true;
    }
  }
  if (endOk && trustedCheckpoint !== null) {
    anchored = canonicalEqual(evidence.end, trustedCheckpoint);
  }

  // 6. optional replay: match inputs by request_id, re-evaluate under recorded pin/time
  let replayResult: Verification["replay"] = "NOT_REQUESTED";
  if (replay && integrity === "VALID") {
    replayResult = replayDecisions(evidence, verified, pins);
  } else if (replay) {
    replayResult = integrity === "INCOMPLETE" ? "CONTEXT_MISSING" : "CONTEXT_MISSING";
  }

  return { integrity, replay: replayResult, through_seq: throughSeq, anchored };
}

function replayDecisions(
  evidence: Evidence,
  entries: AuditEntry[],
  pins: Map<string, { charter: Charter; manifest: Bundle["manifest"] }>,
): Verification["replay"] {
  const inputs = new Map(evidence.inputs.map((i) => [i.request.request_id, i]));
  const pinUpdates = new Map<number, SignedPinUpdate>();
  for (const u of evidence.pin_updates) {
    try {
      vPinUpdate(u.update);
      pinUpdates.set(u.update.expected_revision, u);
    } catch {
      return "CONTEXT_MISSING";
    }
  }
  // pin timeline: PinActivated events give revision→pin
  const activatedPins = new Map<number, Pin>();
  let currentPin: Pin | null = null;
  for (const e of entries) {
    if (e.body.event.type === "PinActivated") {
      currentPin = e.body.event.value.pin;
      activatedPins.set(e.body.event.value.revision, currentPin);
    }
  }
  currentPin = null;
  for (const e of entries) {
    if (e.body.event.type === "PinActivated") {
      currentPin = e.body.event.value.pin;
      continue;
    }
    const t = e.body.event.type;
    if (t !== "CheckEvaluated" && t !== "CallDenied" && t !== "CallDispatched") continue;
    const ev = e.body.event.value;
    const input = inputs.get(ev.request_id);
    if (!input) return "INPUTS_MISSING";
    const inputHash = D("input", { request: input.request, principal: input.principal } as unknown as Json);
    if (inputHash !== ev.input_hash) return "MISMATCH";
    const pin = e.body.policy_pin ?? currentPin;
    if (!pin) return "CONTEXT_MISSING";
    const ctx = pins.get(pinKey(pin));
    if (!ctx) return "CONTEXT_MISSING";
    if (D("charter", ctx.charter) !== pin.charter_hash || D("manifest", ctx.manifest) !== pin.manifest_hash) {
      return "CONTEXT_MISSING";
    }
    const decision: Decision = evaluate({
      charter: ctx.charter, manifest: ctx.manifest, active_pin: pin,
      request: input.request, principal: input.principal, now: ev.evaluated_at,
    });
    if (!canonicalEqual(decision, ev.decision)) return "MISMATCH";
  }
  return "MATCH";
}
