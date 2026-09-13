/**
 * Conformance harness (spec §13.1): fixture expansion, RFC6901 `set` patches,
 * shallow `*_patch` merges, resign support, F-state tenant construction, and
 * the observable projections each op compares.
 */
import { BedrockError } from "../src/errors.js";
import { parseJson, canonicalString, J, type Json } from "../src/canon.js";
import { D, hexDecode } from "../src/crypto.js";
import type {
  Bundle, CallRequest, Charter, Config, EvalInput, Heartbeat, Manifest,
  PauseRequest, Pin, SignedPinUpdate, DisputeRequest, Principal,
} from "../src/types.js";
import { Store } from "../src/server/storage.js";
import { BedrockTenantDO, type Inbound, type DoResponse } from "../src/server/tenant.js";
import { FixtureRecordsAdapter } from "../src/server/adapter.js";
import * as FX from "../src/fixtures.js";
import { parseTime } from "../src/time.js";

// --- fixture expansion --------------------------------------------------------

export const FIXTURES: Record<string, unknown> = {
  C1: FX.C1, C2: FX.C2, B1: FX.B1, B2: FX.B2, R: FX.R, M1: FX.M1,
  P1: FX.P1, P2: FX.P2, U1: FX.U1, E1: FX.E1, E1BODY: FX.E1BODY,
  CP1: FX.CP1, CPBODY: FX.CPBODY, EV1: FX.EV1, Q1: FX.Q1, F: FX.F,
  PRINCIPAL: FX.PRINCIPAL, ALLOW: FX.ALLOW, HB1: FX.HB1, DR1: FX.DR1,
  staleFleet: FX.staleFleet,
};

export function expand(name: string): unknown {
  const v = FIXTURES[name];
  if (v === undefined) throw new Error(`unknown fixture ${name}`);
  return structuredClone(v);
}

/** Expand fixture names inside patch values: "P2" → the P2 object. */
export function expandValue(v: unknown): unknown {
  if (typeof v === "string" && FIXTURES[v] !== undefined) return expand(v);
  return v;
}

/** RFC6901 pointer set on a cloned object. */
export function applySet(doc: unknown, set: Record<string, unknown> | undefined): unknown {
  if (!set) return doc;
  for (const [pointer, rawVal] of Object.entries(set)) {
    const val = expandValue(rawVal);
    if (pointer === "") throw new Error("whole-document set unsupported");
    const segs = pointer.slice(1).split("/").map((s) => s.replace(/~1/g, "/").replace(/~0/g, "~"));
    let cur = doc as Record<string, unknown> | unknown[];
    for (let i = 0; i < segs.length - 1; i++) {
      const s = segs[i]!;
      cur = (Array.isArray(cur) ? cur[Number(s)] : cur[s]) as typeof cur;
      if (cur === undefined || cur === null) throw new Error(`bad pointer ${pointer}`);
    }
    const last = segs[segs.length - 1]!;
    if (Array.isArray(cur)) cur[Number(last)] = val;
    else cur[last] = val;
  }
  return doc;
}

/** Re-sign a charter or pin-update body with seeds 0 and 1 in key order. */
export function resign(kind: "charter" | "pin", obj: Record<string, unknown>): void {
  const body = kind === "charter" ? obj["charter"] : obj["update"];
  obj["signatures"] = [
    { key_id: FX.KA, signature: FX.hexSeedSign(0, kind, body) },
    { key_id: FX.KB, signature: FX.hexSeedSign(1, kind, body) },
  ];
}

// --- tenant construction ------------------------------------------------------

export interface Env {
  dobj: BedrockTenantDO;
  store: Store;
  adapter: FixtureRecordsAdapter;
  now: { ms: number };
  dispatchCount: () => number;
  auditEvents: () => string[];
  config: Config;
}

export function makeConfig(): Config {
  return {
    schema: "bedrock.config/1", environment: "local",
    endpoint: "http://127.0.0.1:8787",
    tenant_id: FX.T, gateway_id: FX.G, instance_id: FX.I,
    system_principal_id: "bpr_SSSSSSSSSSSSSSSSSSSSS",
    root_file: "./trust.json", manifest_file: "./manifest.json",
    instance_inventory: [FX.I],
    client_credential_ref: "env:BEDROCK_CLIENT_CREDENTIAL",
    auth_records_ref: "env:BEDROCK_AUTH_RECORDS",
    audit_seed_ref: "env:BEDROCK_AUDIT_SEED",
    audit_key_id: FX.KC,
    response_keys_ref: "env:BEDROCK_RESPONSE_KEYS",
    storage_soft_limit_bytes: 8589934592,
    max_in_flight: 32,
    metrics_enabled: true,
  };
}

export function newTenant(opts: {
  now?: number;
  faults?: Set<string>;
  store?: Store;
  adapter?: FixtureRecordsAdapter;
} = {}): Env {
  const now = { ms: opts.now ?? parseTime(FX.T0) };
  const adapter = opts.adapter ?? new FixtureRecordsAdapter();
  const store = opts.store ?? new Store(":memory:");
  const dobj = new BedrockTenantDO({
    store,
    config: makeConfig(),
    root: structuredClone(FX.R),
    manifest: structuredClone(FX.M1),
    secrets: {
      authRecords: FX.fixtureAuthRecords(),
      auditSeed: hexDecode(FX.SEEDS[2]!),
      responseKeys: {
        active_key_id: "rk1",
        keys: [{ key_id: "rk1", key_base64url: Buffer.from(new Uint8Array(32).fill(7)).toString("base64url") }],
      },
    },
    adapter,
    nowMs: () => now.ms,
    faults: opts.faults,
  });
  return {
    dobj, store, adapter, now,
    dispatchCount: () => adapter.dispatches,
    auditEvents: () =>
      store.auditRange(0, 1 << 30, 1 << 30).map(
        (r) => (JSON.parse(Buffer.from(r.body_jcs).toString("utf8")) as { event: { type: string } }).event.type,
      ),
    config: makeConfig(),
  };
}

export interface CallSpec {
  method: string;
  path: string;
  role: keyof typeof BEARERS | "none";
  body?: Json;
}

export const BEARERS = {
  agent: FX.BEARER_AGENT,
  operator: FX.BEARER_OPERATOR,
  instance: FX.BEARER_INSTANCE,
  reader: FX.BEARER_READER,
  publisher: FX.BEARER_PUBLISHER,
} as const;

export async function call(env: Env, spec: CallSpec): Promise<DoResponse> {
  const inb: Inbound = {
    method: spec.method,
    path: spec.path,
    headers: {
      authorization: spec.role === "none" ? undefined : `Bearer ${BEARERS[spec.role]}`,
      "x-bedrock-instance": FX.I,
      ...(spec.body !== undefined ? { "content-type": "application/json" } : {}),
    },
    body: spec.body !== undefined ? J(spec.body) : null,
  };
  return env.dobj.fetch(inb);
}

/** Build fixture state F: publish B1, activate U1, heartbeat HB1 — all at T0. */
export async function buildF(opts: { now?: number; store?: Store; adapter?: FixtureRecordsAdapter; faults?: Set<string> } = {}): Promise<Env> {
  const env = newTenant(opts);
  const pub = await call(env, {
    method: "POST", path: "/v1/charter/publish", role: "operator",
    body: { request_id: FX.ID("brq", "V"), bundle: FX.B1 } as unknown as Json,
  });
  if (pub.status !== 201) throw new Error(`F publish failed: ${canonicalString(pub.body)}`);
  const pin = await call(env, {
    method: "POST", path: "/v1/deployment/pin", role: "operator",
    body: FX.U1 as unknown as Json,
  });
  if (pin.status !== 200) throw new Error(`F pin failed: ${canonicalString(pin.body)}`);
  const hb = await call(env, {
    method: "POST", path: "/v1/fleet/heartbeat", role: "instance",
    body: FX.HB1 as unknown as Json,
  });
  if (hb.status !== 200) throw new Error(`F heartbeat failed: ${canonicalString(hb.body)}`);
  return env;
}

/** B1_PUBLISHED: B1 at seq 1, revision 0, UNPINNED, I MISSING, at T0. */
export async function buildB1Published(opts: { now?: number } = {}): Promise<Env> {
  const env = newTenant(opts);
  const pub = await call(env, {
    method: "POST", path: "/v1/charter/publish", role: "operator",
    body: { request_id: FX.ID("brq", "V"), bundle: FX.B1 } as unknown as Json,
  });
  if (pub.status !== 201) throw new Error(`publish failed: ${canonicalString(pub.body)}`);
  return env;
}

export function patchedRequest(patch?: Record<string, unknown>, set?: Record<string, unknown>): CallRequest {
  const req = structuredClone(FX.Q1) as unknown as Record<string, unknown>;
  if (patch) for (const [k, v] of Object.entries(patch)) req[k] = expandValue(v);
  applySet(req, set);
  return req as unknown as CallRequest;
}

export function patchedHeartbeat(patch?: Record<string, unknown>, set?: Record<string, unknown>): Heartbeat {
  const hb = structuredClone(FX.HB1) as unknown as Record<string, unknown>;
  if (patch) for (const [k, v] of Object.entries(patch)) hb[k] = expandValue(v);
  applySet(hb, set);
  return hb as unknown as Heartbeat;
}

export function patchedDispute(patch?: Record<string, unknown>, set?: Record<string, unknown>): DisputeRequest {
  const d = structuredClone(FX.DR1) as unknown as Record<string, unknown>;
  if (patch) for (const [k, v] of Object.entries(patch)) d[k] = expandValue(v);
  applySet(d, set);
  return d as unknown as DisputeRequest;
}

export function pauseBody(revision: number, reason = "Incident containment"): PauseRequest {
  return { request_id: FX.ID("brq", "Z"), expected_revision: revision, reason };
}
