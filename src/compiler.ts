/**
 * Semantic compiler checks (spec §4.1, §5.2): everything structural validation
 * does not cover — sorted sets, authority key uniqueness, lineage binding,
 * exact v1 tool mapping, predicate typing. All failures surface as SCHEMA.
 *
 * Bundle validation order (§5.2): structural schema → manifest digest
 * equality → signature IDs/verification → threshold → semantic compiler →
 * predecessor CAS → publication time bounds.
 */
import { BedrockError } from "./errors.js";
import { canonicalString, type Json } from "./canon.js";
import { D } from "./crypto.js";
import type { Authority, Charter, Field, Manifest, Pin, Predicate, RootFile, Rule, Selector } from "./types.js";
import { vBundle, vCharter, vManifest } from "./schema.js";

function fail(msg: string): never {
  throw new BedrockError("SCHEMA", msg);
}

function utf16cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function jBytesCmp(a: Json, b: Json): number {
  const A = canonicalString(a);
  const B = canonicalString(b);
  return A < B ? -1 : A > B ? 1 : 0;
}

function checkSortedUnique(values: string[], what: string): void {
  for (let i = 1; i < values.length; i++) {
    if (utf16cmp(values[i - 1]!, values[i]!) >= 0) fail(`${what} not sorted/unique`);
  }
}

function checkSortedJ(values: Json[], what: string): void {
  for (let i = 1; i < values.length; i++) {
    if (jBytesCmp(values[i - 1]!, values[i]!) >= 0) fail(`${what} not sorted/unique by J bytes`);
  }
}

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_VALIDITY_MS = 90 * DAY_MS;

export function checkAuthority(a: Authority): void {
  if (a.threshold < 1 || a.threshold > 8) fail("authority threshold outside [1,8]");
  if (a.keys.length > 8) fail("authority has more than 8 keys");
  if (a.threshold > a.keys.length) fail("threshold exceeds key count");
  checkSortedUnique(a.keys.map((k) => k.key_id), "authority keys");
  const pubs = a.keys.map((k) => k.public_key);
  if (new Set(pubs).size !== pubs.length) fail("authority public keys must be distinct");
}

/** The exact v1 RECORDS tool ABI (spec §9.4). */
export const V1_TOOLS: Record<string, { operation: string; args: Field[] }> = {
  "record.delete": { operation: "delete", args: [] },
  "record.export": {
    operation: "export",
    args: [{ name: "destination", kind: "string", max_bytes: 64 }],
  },
  "record.get": { operation: "get", args: [] },
  "record.list": {
    operation: "list",
    args: [{ name: "limit", kind: "integer", min: 1, max: 100 }],
  },
  "record.put": {
    operation: "put",
    args: [{ name: "value", kind: "string", max_bytes: 4096 }],
  },
};

function sameField(a: Field, b: Field): boolean {
  return canonicalString(a) === canonicalString(b);
}

function checkManifestSemantics(manifest: Manifest): void {
  const names = manifest.tools.map((t) => t.tool);
  checkSortedUnique(names, "tools");
  const expected = Object.keys(V1_TOOLS).sort(utf16cmp);
  if (names.length !== expected.length || names.some((n, i) => n !== expected[i])) {
    fail("v1 manifest must contain exactly the five record operations");
  }
  for (const t of manifest.tools) {
    const spec = V1_TOOLS[t.tool]!;
    if (t.binding !== "RECORDS" || t.operation !== spec.operation) {
      fail(`tool ${t.tool} operation/binding mismatch`);
    }
    const argNames = t.args.map((f) => f.name);
    checkSortedUnique(argNames, "fields");
    if (t.args.length !== spec.args.length || !t.args.every((f, i) => sameField(f, spec.args[i]!))) {
      fail(`tool ${t.tool} args differ from the v1 record ABI`);
    }
    for (const f of t.args) {
      if (f.kind === "integer" && f.min > f.max) fail(`field ${f.name} min > max`);
    }
  }
}

function checkRule(r: Rule, deny: boolean, manifest: Manifest, seen: Set<string>): void {
  if (seen.has(r.id)) fail(`rule id ${r.id} not unique across rule lists`);
  seen.add(r.id);
  const mtools = new Map(manifest.tools.map((t) => [t.tool, t]));
  checkSortedUnique(r.principals, "principals");
  checkSortedUnique(r.tools, "tools");
  checkSortedUnique(r.scopes, "scopes");
  checkSortedJ(r.resources as Json[], "resources");
  checkSortedJ(r.when as Json[], "predicates");
  if (r.principals.includes("*") && r.principals.length !== 1) fail("wildcard principal must stand alone");
  if (r.scopes.includes("*") && r.scopes.length !== 1) fail("wildcard scope must stand alone");
  if (!deny) {
    if (r.scopes.includes("*")) fail("allow rules may not use scope wildcard");
    if (r.resources.some((s) => s.match === "all")) fail("allow rules may not use match=all");
  }
  for (const t of r.tools) {
    if (!mtools.has(t)) fail(`rule ${r.id} references unknown tool ${t}`);
  }
  for (const p of r.when) {
    let type: Field["kind"] | null = null;
    for (const tn of r.tools) {
      const f = mtools.get(tn)!.args.find((a) => a.name === p.arg);
      if (!f) fail(`predicate arg ${p.arg} not a field of tool ${tn}`);
      if (type === null) type = f.kind;
      else if (type !== f.kind) fail(`predicate arg ${p.arg} has inconsistent types across tools`);
    }
    if (p.op === "int_lte" && type !== "integer") {
      fail(`int_lte predicate on non-integer arg ${p.arg}`);
    }
    if (p.op === "eq") {
      const v = p.value;
      if (type === "integer" && typeof v !== "number") fail("eq predicate type mismatch");
      if (type === "string" && typeof v !== "string") fail("eq predicate type mismatch");
      if (type === "boolean" && typeof v !== "boolean") fail("eq predicate type mismatch");
    }
  }
}

function checkCharterSemantics(charter: Charter, manifest: Manifest): void {
  if (charter.version < 1) fail("version must be >= 1");
  if (charter.version === 1 && charter.previous_hash !== null) {
    fail("genesis requires previous_hash null");
  }
  if (charter.version > 1 && charter.previous_hash === null) {
    fail("successor requires previous_hash");
  }
  const issued = Date.parse(charter.issued_at);
  const nb = Date.parse(charter.not_before);
  const na = Date.parse(charter.not_after);
  if (!(issued <= nb)) fail("issued_at must be <= not_before");
  if (!(nb < na)) fail("not_before must be < not_after");
  if (na - nb > MAX_VALIDITY_MS) fail("validity span exceeds 90 days");
  checkAuthority(charter.next_authority);
  const total = charter.hard_denies.length + charter.scope_rules.length;
  if (total > 128) fail("charter exceeds 128 rules");
  checkSortedUnique(charter.hard_denies.map((r) => r.id), "hard_deny rule ids");
  checkSortedUnique(charter.scope_rules.map((r) => r.id), "scope rule ids");
  const seen = new Set<string>();
  for (const r of charter.hard_denies) checkRule(r, true, manifest, seen);
  for (const r of charter.scope_rules) checkRule(r, false, manifest, seen);
}

export interface Compiled {
  charter_hash: string;
  manifest_hash: string;
  engine: "bedrock.eval/1";
}

/**
 * Full offline compile for the CLI/SDK: structural schema, manifest digest
 * equality, then all semantic checks.
 */
export function compile(charter: Charter, manifest: Manifest): Compiled {
  vCharter(charter);
  vManifest(manifest);
  const manifestHash = manifestDigestOrThrow(charter, manifest);
  checkManifestSemantics(manifest);
  checkCharterSemantics(charter, manifest);
  return { charter_hash: D("charter", charter), manifest_hash: manifestHash, engine: "bedrock.eval/1" };
}

export function manifestDigestOrThrow(charter: Charter, manifest: Manifest): string {
  const manifestHash = D("manifest", manifest);
  if (charter.manifest_hash !== manifestHash) {
    throw new BedrockError("HASH_MISMATCH", "charter manifest_hash does not match manifest digest");
  }
  return manifestHash;
}

export function checkBundleSemantics(charter: Charter, manifest: Manifest): void {
  checkManifestSemantics(manifest);
  checkCharterSemantics(charter, manifest);
}

/** Lineage binding against the operator-pinned root file (spec §5.2). */
export function checkLineage(charter: Charter, manifest: Manifest, root: RootFile): void {
  if (charter.tenant_id !== root.tenant_id) fail("charter tenant_id does not match root");
  if (charter.charter_id !== root.charter_id) fail("charter_id does not match root");
  if (manifest.gateway_id !== root.gateway_id) fail("manifest gateway_id does not match root");
}

export function pinOf(charter: Charter, manifestHash: string): Pin {
  return {
    charter_id: charter.charter_id,
    version: charter.version,
    charter_hash: D("charter", charter),
    manifest_hash: manifestHash,
    engine: charter.engine,
  };
}
