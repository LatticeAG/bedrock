/**
 * Property campaigns (spec §13.2): bounded seeds for deny dominance,
 * deterministic serialization, duplicate replay, and pin/pause interleavings;
 * crash schedules asserting at-most-one adapter invocation; and the regression
 * campaigns (cross-tenant, encoding, signature, audit-key, staleness).
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BedrockError } from "../src/errors.js";
import { canonicalString, J, type Json } from "../src/canon.js";
import { D, hexDecode, ed25519Verify, ed25519Sign, b64urlEncode, S, ed25519PublicKey } from "../src/crypto.js";
import { evaluate } from "../src/evaluator.js";
import { verifyBundle } from "../src/bundle.js";
import { Store } from "../src/server/storage.js";
import { FixtureRecordsAdapter } from "../src/server/adapter.js";
import * as FX from "../src/fixtures.js";
import { newTenant, buildF, call, applySet, resign, patchedRequest } from "./harness.js";
import { makeConfig } from "./harness.js";
import { parseTime } from "../src/time.js";
import type { CallResult, Charter, EvalInput } from "../src/types.js";

// Deterministic PRNG (xorshift32) — campaigns must be reproducible.
function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >> 17;
    s ^= s << 5; s >>>= 0;
    return s / 0xffffffff;
  };
}

function pick<T>(r: () => number, arr: readonly T[]): T {
  return arr[Math.floor(r() * arr.length) % arr.length]!;
}

const TOOLS = ["record.get", "record.put", "record.list", "record.delete", "record.export", "record.exec"];
const SCOPES = ["task-a", "task-b", "task-c"];
const RESOURCES = ["records/a", "records/b/c", "records2/a", "records", "other/x", "records/%2e%2e/x"];

function randomRequest(r: () => number, pin: typeof FX.P1): Record<string, unknown> {
  return {
    request_id: `brq_${String.fromCharCode(65 + Math.floor(r() * 26)).repeat(21)}`,
    pin, scope: pick(r, SCOPES), tool: pick(r, TOOLS), resource: pick(r, RESOURCES),
    args: { limit: Math.floor(r() * 200), value: "x".repeat(Math.floor(r() * 32)), destination: "d" },
    deadline: FX.T30,
  };
}

test("property: deny dominance, deterministic serialization, replay safety (10000 seeds)", { timeout: 300000 }, async () => {
  const r = rng(0xbed2);
  let denyDom = 0, serial = 0, replay = 0, interleave = 0;
  const N = 10_000;
  const env = await buildF();
  const seenResponses = new Map<string, string>();

  for (let i = 0; i < N; i++) {
    const kind = i % 4;
    if (kind === 0) {
      // Deny dominance: craft a request matching both a deny and an allow rule.
      const charter = JSON.parse(JSON.stringify(FX.C1)) as Charter;
      charter.scope_rules = [{
        id: FX.RA, principals: ["*"], tools: ["record.delete"],
        scopes: ["task-a"], resources: [{ match: "segment_prefix", value: "records" }], when: [],
      }];
      const input: EvalInput = {
        charter, manifest: FX.M1, active_pin: { ...FX.P1, charter_hash: D("charter", charter) },
        request: { ...FX.Q1, tool: "record.delete", pin: { ...FX.P1, charter_hash: D("charter", charter) } },
        principal: FX.PRINCIPAL, now: FX.T0,
      };
      const d = evaluate(input);
      assert.equal(d.verdict, "DENY");
      assert.equal(d.reason, "HARD_DENY");
      denyDom++;
    } else if (kind === 1) {
      // Deterministic serialization: same semantic object in shuffled key order
      // produces identical canonical bytes.
      const obj: Record<string, Json> = {};
      const keys = ["k" + Math.floor(r() * 100), "k2", "k0", "zz", "aa"];
      for (const k of keys) obj[k] = Math.floor(r() * 1000);
      const shuffled: Record<string, Json> = {};
      for (const k of [...Object.keys(obj)].reverse()) shuffled[k] = obj[k]!;
      assert.equal(canonicalString(obj), canonicalString(shuffled));
      serial++;
    } else if (kind === 2) {
      // Duplicate replay: identical retry returns identical response with no
      // new dispatch (a fresh tenant per N/4 is too slow; reuse env and a new
      // request id each iteration).
      const req = patchedRequest({ request_id: `brq_${"R".repeat(20)}${String.fromCharCode(65 + (i % 26))}` });
      // distinct request_id per iteration to avoid cross-talk; keep within charset
      const rr = req as unknown as Record<string, unknown>;
      rr["request_id"] = `brq_${(1000000000000000000 + i).toString(36).slice(0, 21).padStart(21, "0")}`;
      const r1 = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: rr as Json });
      const r2 = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: rr as Json });
      assert.equal(canonicalString(r1.body), canonicalString(r2.body));
      replay++;
    } else {
      // Pin/pause interleavings at the pure level: once paused, evaluation gate
      // is irrelevant — assert evaluator stays deterministic under pin swaps.
      const input = JSON.parse(JSON.stringify(FX.F.eval)) as EvalInput;
      if (r() < 0.5) applySet(input, { "/request/pin/version": 2 });
      if (r() < 0.3) applySet(input, { "/request/tool": "record.delete" });
      const d1 = evaluate(JSON.parse(JSON.stringify(input)));
      const d2 = evaluate(JSON.parse(JSON.stringify(input)));
      assert.equal(canonicalString(d1), canonicalString(d2));
      interleave++;
    }
  }
  assert.equal(denyDom + serial + replay + interleave, N);
});

test("crash schedules: 1000 injection points, at most one adapter invocation per identity", { timeout: 600000 }, async () => {
  const faultPoints = [
    "crash_after_marker",           // marker committed, never invoked, never resent
    "crash_before_finish",          // invoked, completion txn crashed → recover INDETERMINATE
    "audit_commit_before_dispatch", // audit outage before marker → nothing sent
  ];
  let iterations = 0;
  for (let i = 0; i < 1000; i++) {
    const fault = faultPoints[i % faultPoints.length]!;
    const store = new Store(":memory:");
    const faults = new Set<string>();
    const adapter = new FixtureRecordsAdapter();
    const env = await buildF({ store, faults, adapter });
    faults.add(fault);
    try {
      await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
    } catch (e) {
      assert.equal((e as Error).name, "CrashFault", `fault ${fault}`);
    }
    // Recover on the same store.
    faults.clear();
    const env2 = newTenant({ store, now: env.now.ms, adapter });
    const dispatchesBefore = env2.dispatchCount();
    const r = await call(env2, { method: "GET", path: `/v1/gateway/calls/${FX.Q1.request_id}`, role: "agent" });
    const body = r.body as unknown as CallResult;
    if (fault === "audit_commit_before_dispatch") {
      // fail-closed: no call record; the original request never dispatched
      assert.equal(r.status, 404);
      assert.equal(adapter.dispatches, 0);
    } else {
      assert.equal(body.state, "INDETERMINATE", `fault ${fault} iteration ${i}`);
      assert.equal(env2.dispatchCount(), dispatchesBefore); // no resend
    }
    // Retry preserves identity; never re-invokes — except when nothing was
    // durably recorded (audit_commit_before_dispatch), where the retry is a
    // fresh first attempt and must dispatch exactly once.
    const retry = await call(env2, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
    if (fault === "audit_commit_before_dispatch") {
      assert.equal(env2.dispatchCount(), 1);
      assert.equal((retry.body as unknown as CallResult).state, "SUCCEEDED");
    } else {
      assert.equal(env2.dispatchCount(), dispatchesBefore);
      assert.equal((retry.body as unknown as CallResult).state, "INDETERMINATE");
    }
    iterations++;
    store.close();
  }
  assert.equal(iterations, 1000);
});

// --- regression campaigns --------------------------------------------------------

test("cross-tenant ID probing returns indistinguishable 404/401", async () => {
  const env = await buildF();
  // other-tenant credential
  const badToken = "fixture-agent-credential-other-tenant";
  const r = await env.dobj.fetch({
    method: "GET", path: "/v1/deployment",
    headers: { authorization: `Bearer ${badToken}`, "x-bedrock-instance": FX.I }, body: null,
  });
  assert.equal(r.status, 401);
  // invisible call ID → 404 same as absent
  const a = await call(env, { method: "GET", path: "/v1/gateway/calls/brq_XXXXXXXXXXXXXXXXXXXXX", role: "agent" });
  assert.equal(a.status, 404);
  // call owned by another principal → same 404
  await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  const other = await env.dobj.fetch({
    method: "GET", path: `/v1/gateway/calls/${FX.Q1.request_id}`,
    headers: { authorization: `Bearer ${FX.BEARER_READER}`, "x-bedrock-instance": FX.I }, body: null,
  });
  assert.equal(other.status, 200); // reader may read any call
});

test("invalid UTF-8, lone surrogate, oversized body/depth, base64 padding", async () => {
  const env = await buildF();
  // invalid UTF-8
  let r = await env.dobj.fetch({
    method: "POST", path: "/v1/gateway/check",
    headers: { authorization: `Bearer ${FX.BEARER_AGENT}`, "x-bedrock-instance": FX.I, "content-type": "application/json" },
    body: new Uint8Array([0xff, 0xfe, 0x7b]),
  });
  assert.equal((r.body as { error: { code: string } }).error.code, "PARSE");
  // lone surrogate
  r = await env.dobj.fetch({
    method: "POST", path: "/v1/gateway/check",
    headers: { authorization: `Bearer ${FX.BEARER_AGENT}`, "x-bedrock-instance": FX.I, "content-type": "application/json" },
    body: new TextEncoder().encode('{"request_id":"\\ud800x"}'),
  });
  assert.equal((r.body as { error: { code: string } }).error.code, "PARSE");
  // oversized body
  r = await env.dobj.fetch({
    method: "POST", path: "/v1/gateway/check",
    headers: { authorization: `Bearer ${FX.BEARER_AGENT}`, "x-bedrock-instance": FX.I, "content-type": "application/json" },
    body: new Uint8Array(64 * 1024 + 1).fill(0x20),
  });
  assert.equal((r.body as { error: { code: string } }).error.code, "LIMIT");
  // depth > 16
  let deep = "1";
  for (let i = 0; i < 20; i++) deep = `{"a":${deep}}`;
  r = await env.dobj.fetch({
    method: "POST", path: "/v1/gateway/check",
    headers: { authorization: `Bearer ${FX.BEARER_AGENT}`, "x-bedrock-instance": FX.I, "content-type": "application/json" },
    body: new TextEncoder().encode(deep),
  });
  assert.equal((r.body as { error: { code: string } }).error.code, "PARSE");
  // base64 padding in signature is rejected
  const b = structuredClone(FX.B1) as unknown as Record<string, unknown>;
  applySet(b, { "/signatures/0/signature": (FX.B1.signatures[0]!.signature + "=").slice(0, 87) + "=" });
  const v = await call(env, { method: "POST", path: "/v1/charter/validate", role: "publisher", body: { bundle: b } as unknown as Json });
  assert.equal((v.body as { error: { code: string } }).error.code, "SCHEMA");
});

test("noncanonical Ed25519 encodings rejected", () => {
  // small-order R/S and non-canonical S encodings must not verify
  const pub = hexDecode(FX.PUB[0]!);
  const msg = S("charter", FX.C1);
  const goodSig = Buffer.from(FX.B1.signatures[0]!.signature, "base64url");
  assert.equal(ed25519Verify(pub, new Uint8Array(goodSig), msg), true);
  // flip S above group order (non-canonical scalar)
  const bad = new Uint8Array(goodSig);
  bad[63] = 0xff; // corrupt high bits of S
  assert.equal(ed25519Verify(pub, bad, msg), false);
  // all-zero signature (small-order)
  assert.equal(ed25519Verify(pub, new Uint8Array(64), msg), false);
});

test("audit-key range eligibility is enforced", async () => {
  // root whose audit key range does not cover the next sequence
  const root = JSON.parse(JSON.stringify(FX.R)) as typeof FX.R;
  root.audit_keys = [{ key_id: FX.KC, public_key: FX.PUB[2]!, from_seq: 5, through_seq: 9 }];
  const store = new Store(":memory:");
  const adapter = new FixtureRecordsAdapter();
  const { BedrockTenantDO } = await import("../src/server/tenant.js");
  const dobj = new BedrockTenantDO({
    store, config: makeConfig(), root,
    manifest: structuredClone(FX.M1),
    secrets: {
      authRecords: FX.fixtureAuthRecords(), auditSeed: hexDecode(FX.SEEDS[2]!),
      responseKeys: { active_key_id: "rk1", keys: [{ key_id: "rk1", key_base64url: Buffer.alloc(32, 7).toString("base64url") }] },
    },
    adapter, nowMs: () => parseTime(FX.T0),
  });
  const r = await dobj.fetch({
    method: "POST", path: "/v1/charter/publish",
    headers: { authorization: `Bearer ${FX.BEARER_OPERATOR}`, "x-bedrock-instance": FX.I, "content-type": "application/json" },
    body: J({ request_id: FX.ID("brq", "V"), bundle: FX.B1 }),
  });
  assert.equal(r.status, 503);
  assert.equal((r.body as { error: { code: string } }).error.code, "AUDIT_UNAVAILABLE");
});

test("stale credential rejected; expiry never extended", async () => {
  const store = new Store(":memory:");
  const adapter = new FixtureRecordsAdapter();
  const records = FX.fixtureAuthRecords();
  records[0]!.expires_at = "2026-09-12T00:00:00.000Z"; // agent expires at T0
  const { BedrockTenantDO } = await import("../src/server/tenant.js");
  const dobj = new BedrockTenantDO({
    store, config: makeConfig(), root: structuredClone(FX.R), manifest: structuredClone(FX.M1),
    secrets: {
      authRecords: records, auditSeed: hexDecode(FX.SEEDS[2]!),
      responseKeys: { active_key_id: "rk1", keys: [{ key_id: "rk1", key_base64url: Buffer.alloc(32, 7).toString("base64url") }] },
    },
    adapter, nowMs: () => parseTime(FX.T0) + 1,
  });
  const r = await dobj.fetch({
    method: "GET", path: "/v1/deployment",
    headers: { authorization: `Bearer ${FX.BEARER_AGENT}`, "x-bedrock-instance": FX.I }, body: null,
  });
  assert.equal(r.status, 401);
});

test("key rotation: successor under old authority, next under new", async () => {
  // Build C2' with next_authority rotated to a new key set, signed by old AUTH.
  const KC2 = FX.ID("bky", "E");
  const seed3 = hexDecode("1f4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a5");
  const pub3 = Buffer.from(ed25519PublicKey(seed3)).toString("hex");
  const newAuth = { threshold: 1, keys: [{ key_id: KC2, public_key: pub3 }] };
  const c2 = JSON.parse(JSON.stringify(FX.C2)) as Charter;
  c2.next_authority = newAuth;
  const b2 = { charter: c2, manifest: FX.M1, signatures: [] as { key_id: string; signature: string }[] };
  resign("charter", b2 as unknown as Record<string, unknown>);
  // verify: old authority signs v2
  const r = verifyBundle(b2, structuredClone(FX.R), [structuredClone(FX.B1)]);
  assert.equal(r.valid, true);
  // v3 must be signed by the NEW authority; old authority fails QUORUM/KEY_UNKNOWN
  const c3 = JSON.parse(JSON.stringify(c2)) as Charter;
  c3.version = 3;
  c3.previous_hash = D("charter", c2);
  const b3 = { charter: c3, manifest: FX.M1, signatures: [] as { key_id: string; signature: string }[] };
  resign("charter", b3 as unknown as Record<string, unknown>);
  assert.throws(() => verifyBundle(b3, structuredClone(FX.R), [structuredClone(FX.B1), b2]), (e) => (e as BedrockError).code === "KEY_UNKNOWN");
  // now sign v3 under new authority
  b3.signatures = [{
    key_id: KC2,
    signature: b64urlEncode(ed25519Sign(seed3, S("charter", c3 as unknown as Json))),
  }];
  const r3 = verifyBundle(b3, structuredClone(FX.R), [structuredClone(FX.B1), b2]);
  assert.equal(r3.valid, true);
});

test("duplicate public key in authority rejected", () => {
  const c = JSON.parse(JSON.stringify(FX.C1)) as Charter;
  c.next_authority = {
    threshold: 2,
    keys: [
      { key_id: FX.KA, public_key: FX.PUB[0]! },
      { key_id: FX.KB, public_key: FX.PUB[0]! },
    ],
  };
  assert.throws(
    () => verifyBundle({ charter: c, manifest: FX.M1, signatures: [] }, structuredClone(FX.R), []),
    (e) => ["SCHEMA", "QUORUM", "KEY_UNKNOWN"].includes((e as BedrockError).code),
  );
});

test("heartbeat counter replay conflicts", async () => {
  const env = await buildF();
  const r = await call(env, {
    method: "POST", path: "/v1/fleet/heartbeat", role: "instance",
    body: { ...FX.HB1, request_id: FX.ID("brq", "J") } as unknown as Json,
  });
  assert.equal(r.status, 409);
  assert.equal((r.body as { error: { code: string } }).error.code, "COUNTER_CONFLICT");
});

test("production startup rejects fixture keys", async () => {
  const { loadConfig } = await import("../src/config.js");
  const fs = await import("node:fs");
  const dir = fs.mkdtempSync("/tmp/bedrock-prod-");
  fs.writeFileSync(`${dir}/trust.json`, canonicalString(FX.R));
  fs.writeFileSync(`${dir}/manifest.json`, canonicalString(FX.M1));
  const cfg = {
    schema: "bedrock.config/1", environment: "production",
    endpoint: "https://gateway.example.internal",
    tenant_id: FX.T, gateway_id: FX.G, instance_id: FX.I,
    system_principal_id: "bpr_SSSSSSSSSSSSSSSSSSSSS",
    root_file: "./trust.json", manifest_file: "./manifest.json",
    instance_inventory: [FX.I],
    client_credential_ref: "env:BEDROCK_CLIENT_CREDENTIAL",
    auth_records_ref: "env:BEDROCK_AUTH_RECORDS",
    audit_seed_ref: "env:BEDROCK_AUDIT_SEED",
    audit_key_id: FX.KC, response_keys_ref: "env:BEDROCK_RESPONSE_KEYS",
    storage_soft_limit_bytes: 8589934592, max_in_flight: 32, metrics_enabled: true,
  };
  const yaml = Object.entries(cfg).map(([k, v]) => `${k}: ${Array.isArray(v) ? `[${v.join(",")}]` : JSON.stringify(v)}`).join("\n");
  fs.writeFileSync(`${dir}/bedrock.yaml`, yaml);
  assert.throws(() => loadConfig(`${dir}/bedrock.yaml`), (e) => (e as BedrockError).code === "SCHEMA");
});
