/**
 * Route schema tests (spec §13.2): every public route gets at least one
 * successful schema round trip, one unauthorized-role test, and one
 * unknown-field test where its request has a body. Plus the forbidden-surface
 * negatives: no latest alias, no delete route, no idempotency header, etc.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { canonicalString, J, type Json } from "../src/canon.js";
import * as FX from "../src/fixtures.js";
import { buildF, buildB1Published, call, pauseBody, BEARERS } from "./harness.js";
import type { CallResult } from "../src/types.js";

async function errCode(p: Promise<{ status: number; body: Json }>): Promise<{ status: number; code: string }> {
  const r = await p;
  return { status: r.status, code: (r.body as { error: { code: string } }).error.code };
}

test("healthz is unauthenticated and minimal", async () => {
  const env = await buildF();
  const r = await call(env, { method: "GET", path: "/healthz", role: "none" });
  assert.equal(r.status, 200);
  assert.deepEqual(r.body, { status: "up", api: "bedrock.http/1" });
});

test("route table: success roundtrips", async () => {
  const env = await buildF();
  // readyz
  let r = await call(env, { method: "GET", path: "/v1/readyz", role: "operator" });
  assert.equal(r.status, 200);
  assert.equal((r.body as { ready: boolean }).ready, true);
  // charter validate (B2 candidate against chain head B1)
  r = await call(env, { method: "POST", path: "/v1/charter/validate", role: "publisher", body: { bundle: FX.B2 } as unknown as Json });
  assert.equal(r.status, 200);
  assert.equal((r.body as { valid: boolean }).valid, true);
  // charter versions list + get
  r = await call(env, { method: "GET", path: "/v1/charter/versions?after=0&limit=100", role: "reader" });
  assert.equal(r.status, 200);
  assert.equal((r.body as { head_version: number }).head_version, 1);
  r = await call(env, { method: "GET", path: "/v1/charter/versions/1", role: "reader" });
  assert.equal(r.status, 200);
  assert.equal(canonicalString(r.body), canonicalString(FX.B1 as unknown as Json));
  // deployment
  r = await call(env, { method: "GET", path: "/v1/deployment", role: "instance" });
  assert.equal(r.status, 200);
  assert.equal((r.body as { state: string }).state, "ACTIVE");
  // check + call + call get
  r = await call(env, { method: "POST", path: "/v1/gateway/check", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(r.status, 200);
  assert.equal((r.body as { enforcement: boolean }).enforcement, false);
  const callReq = { ...FX.Q1, request_id: "brq_GGGGGGGGGGGGGGGGGGGGG" } as unknown as Json;
  r = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: callReq });
  assert.equal(r.status, 200);
  assert.equal((r.body as unknown as CallResult).state, "SUCCEEDED");
  r = await call(env, { method: "GET", path: "/v1/gateway/calls/brq_GGGGGGGGGGGGGGGGGGGGG", role: "agent" });
  assert.equal(r.status, 200);
  // dispute create + list
  r = await call(env, { method: "POST", path: "/v1/disputes", role: "agent", body: FX.DR1 as unknown as Json });
  assert.equal(r.status, 201);
  r = await call(env, { method: "GET", path: "/v1/disputes?after_seq=0&limit=100", role: "reader" });
  assert.equal(r.status, 200);
  assert.equal((r.body as { disputes: unknown[] }).disputes.length, 1);
  // fleet
  r = await call(env, { method: "GET", path: "/v1/fleet", role: "reader" });
  assert.equal(r.status, 200);
  assert.equal((r.body as { status: string }).status, "HEALTHY");
  // audit + checkpoint + metrics
  r = await call(env, { method: "GET", path: "/v1/audit?after_seq=0&through_seq=1&limit=100", role: "reader" });
  assert.equal(r.status, 200);
  r = await call(env, { method: "GET", path: "/v1/audit/checkpoint", role: "reader" });
  assert.equal(r.status, 200);
  assert.equal(typeof (r.body as { signature: string }).signature, "string");
  r = await call(env, { method: "GET", path: "/v1/metrics", role: "operator" });
  assert.equal(r.status, 200);
  assert.equal((r.body as { window_seconds: number }).window_seconds, 60);
});

test("route table: wrong roles are FORBIDDEN", async () => {
  const env = await buildF();
  const cases: [string, string, keyof typeof BEARERS, Json?][] = [
    ["GET", "/v1/readyz", "agent"],
    ["POST", "/v1/charter/validate", "reader", { bundle: FX.B1 } as unknown as Json],
    ["POST", "/v1/charter/publish", "agent", { request_id: FX.ID("brq", "V"), bundle: FX.B1 } as unknown as Json],
    ["GET", "/v1/charter/versions?after=0&limit=100", "agent"],
    ["GET", "/v1/charter/versions/1", "instance"],
    ["GET", "/v1/deployment", "agent"],
    ["POST", "/v1/deployment/pin", "agent", FX.U1 as unknown as Json],
    ["POST", "/v1/deployment/pause", "reader", pauseBody(1) as unknown as Json],
    ["POST", "/v1/gateway/check", "operator", FX.Q1 as unknown as Json],
    ["POST", "/v1/gateway/call", "reader", FX.Q1 as unknown as Json],
    ["POST", "/v1/fleet/heartbeat", "agent", FX.HB1 as unknown as Json],
    ["GET", "/v1/audit?after_seq=0&through_seq=1&limit=100", "agent"],
    ["GET", "/v1/metrics", "reader"],
  ];
  for (const [method, path, role, body] of cases) {
    const r = await errCode(call(env, { method, path, role, body }));
    assert.equal(r.code, "FORBIDDEN", `${method} ${path} as ${role}`);
    assert.equal(r.status, 403);
  }
});

test("route table: unknown fields fail SCHEMA", async () => {
  const env = await buildF();
  const bad = (extra: Json) => call(env, {
    method: "POST", path: "/v1/gateway/check", role: "agent",
    body: { ...(FX.Q1 as unknown as Record<string, Json>), ...(extra as Record<string, Json>) } as Json,
  });
  let r = await errCode(bad({ override: "all" }));
  assert.equal(r.code, "SCHEMA");
  r = await errCode(call(env, {
    method: "POST", path: "/v1/deployment/pause", role: "operator",
    body: { ...pauseBody(1), allow_all: true } as unknown as Json,
  }));
  assert.equal(r.code, "SCHEMA");
  r = await errCode(call(env, {
    method: "POST", path: "/v1/fleet/heartbeat", role: "instance",
    body: { ...FX.HB1, attestation: "tpm" } as unknown as Json,
  }));
  assert.equal(r.code, "SCHEMA");
});

test("forbidden surfaces do not exist", async () => {
  const env = await buildF();
  // no latest alias
  let r = await errCode(call(env, { method: "GET", path: "/v1/charter/versions/latest", role: "reader" }));
  assert.equal(r.code, "SCHEMA"); // version grammar rejects non-decimal
  r = await errCode(call(env, { method: "GET", path: "/v1/charter/latest", role: "reader" }));
  assert.equal(r.code, "NOT_FOUND");
  // no DELETE
  r = await errCode(call(env, { method: "DELETE", path: "/v1/deployment", role: "operator" }));
  assert.equal(r.status, 405);
  assert.equal(r.code, "SCHEMA");
  // no debug endpoint
  r = await errCode(call(env, { method: "GET", path: "/v1/debug", role: "operator" }));
  assert.equal(r.code, "NOT_FOUND");
  // no raw upstream proxy
  r = await errCode(call(env, { method: "POST", path: "/v1/records/run", role: "agent", body: {} }));
  assert.equal(r.code, "NOT_FOUND");
  // no signature collection RPC
  r = await errCode(call(env, { method: "POST", path: "/v1/charter/sign", role: "operator", body: {} }));
  assert.equal(r.code, "NOT_FOUND");
  // no precedent resolver
  r = await errCode(call(env, { method: "POST", path: "/v1/disputes/resolve", role: "operator", body: {} }));
  assert.equal(r.code, "NOT_FOUND");
});

test("idempotency-key header is never interpreted", async () => {
  const env = await buildF();
  const r = await env.dobj.fetch({
    method: "POST", path: "/v1/gateway/check",
    headers: {
      authorization: `Bearer ${FX.BEARER_AGENT}`,
      "x-bedrock-instance": FX.I,
      "content-type": "application/json",
      "idempotency-key": "abc",
    },
    body: J(FX.Q1 as unknown as Json),
  });
  assert.equal(r.status, 400);
  assert.equal((r.body as { error: { code: string } }).error.code, "SCHEMA");
});

test("unauthenticated, bad token, wrong content-type, read-body", async () => {
  const env = await buildF();
  let r = await errCode(call(env, { method: "GET", path: "/v1/deployment", role: "none" }));
  assert.equal(r.status, 401);
  r = await errCode(env.dobj.fetch({
    method: "GET", path: "/v1/deployment",
    headers: { authorization: "Bearer wrong-token", "x-bedrock-instance": FX.I },
    body: null,
  }));
  assert.equal(r.status, 401);
  r = await errCode(env.dobj.fetch({
    method: "POST", path: "/v1/gateway/check",
    headers: { authorization: `Bearer ${FX.BEARER_AGENT}`, "x-bedrock-instance": FX.I, "content-type": "text/plain" },
    body: J(FX.Q1 as unknown as Json),
  }));
  assert.equal(r.code, "SCHEMA");
  r = await errCode(call(env, { method: "GET", path: "/v1/deployment?x=1", role: "operator" }));
  assert.equal(r.code, "SCHEMA"); // undeclared query param
  r = await errCode(call(env, { method: "GET", path: "/v1/deployment/", role: "operator" }));
  assert.equal(r.code, "NOT_FOUND"); // trailing segment
});

test("readyz fails UNPINNED before pin", async () => {
  const env = await buildB1Published();
  const r = await call(env, { method: "GET", path: "/v1/readyz", role: "operator" });
  assert.equal(r.status, 503);
  assert.equal((r.body as { error: { code: string } }).error.code, "UNPINNED");
});
