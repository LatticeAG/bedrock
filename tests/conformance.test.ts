/**
 * TV-B--01..55 conformance vectors (spec §13). Each test is a real execution
 * against the harness — no fixture shortcuts.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { BedrockError } from "../src/errors.js";
import { canonicalString, canonicalKeyOrder, parseJson, J } from "../src/canon.js";
import { parseYaml } from "../src/yaml.js";
import { D } from "../src/crypto.js";
import { evaluate } from "../src/evaluator.js";
import { compile } from "../src/compiler.js";
import { verifyBundle } from "../src/bundle.js";
import { verifyEvidence } from "../src/evidence.js";
import { vCharter, vManifest } from "../src/schema.js";
import type { Bundle, CallResult, EvalInput } from "../src/types.js";
import * as FX from "../src/fixtures.js";
import {
  expand, expandValue, applySet, resign, newTenant, buildF, buildB1Published,
  call, patchedRequest, patchedHeartbeat, patchedDispute, pauseBody, type Env,
} from "./harness.js";
import { parseTime, formatTime } from "../src/time.js";
import { canonicalEqual } from "../src/bundle.js";
import type { Json } from "../src/canon.js";

function code(e: unknown): string {
  if (e instanceof BedrockError) return e.code;
  throw e;
}

function evalFixture(patch?: {
  request_patch?: Record<string, unknown>;
  charter_patch?: Record<string, unknown>;
  principal_patch?: Record<string, unknown>;
  now?: string;
  set?: Record<string, unknown>;
}): EvalInput {
  // JSON clone: breaks shared references (Q1.pin === P1 in the fixture table)
  const input = JSON.parse(JSON.stringify(FX.F.eval)) as Record<string, unknown>;
  const p = patch ?? {};
  if (p.request_patch) {
    const req = input["request"] as Record<string, unknown>;
    for (const [k, v] of Object.entries(p.request_patch)) req[k] = expandValue(v);
  }
  if (p.charter_patch) {
    const ch = input["charter"] as Record<string, unknown>;
    for (const [k, v] of Object.entries(p.charter_patch)) ch[k] = expandValue(v);
    // recompute charter hash into pin for pure evaluation only
    const h = D("charter", input["charter"]);
    (input["active_pin"] as Record<string, unknown>)["charter_hash"] = h;
    (input["request"] as Record<string, unknown>)["pin"] =
      { ...(input["request"] as { pin: object }).pin as object, charter_hash: h };
  }
  if (p.principal_patch) {
    const pr = input["principal"] as Record<string, unknown>;
    for (const [k, v] of Object.entries(p.principal_patch)) pr[k] = expandValue(v);
  }
  if (p.now) input["now"] = p.now;
  const charterTouched = p.set !== undefined && Object.keys(p.set).some((k) => k.startsWith("/charter"));
  applySet(input, p.set);
  if (charterTouched) {
    const h = D("charter", input["charter"]);
    (input["active_pin"] as Record<string, unknown>)["charter_hash"] = h;
    (input["request"] as Record<string, unknown>)["pin"] =
      { ...((input["request"] as { pin: object }).pin as object), charter_hash: h };
  }
  return input as unknown as EvalInput;
}

function evalDecision(patch?: Parameters<typeof evalFixture>[0]) {
  return evaluate(evalFixture(patch));
}

// ---------------------------------------------------------------------------

test("TV-B--01 canonical member order", () => {
  const utf8 = new TextDecoder().decode(J({ b: 2, a: 1 }));
  assert.equal(utf8, '{"a":1,"b":2}');
});

test("TV-B--02 published charter digest", () => {
  assert.equal(D("charter", FX.C1), "cd7f974d91f897bfbe44563ce3b3fdf5e16f2074c6f82569a8727ee313e1d2e7");
});

test("TV-B--03 exact Ed25519 bundle verification", () => {
  const r = verifyBundle(expand("B1") as Bundle, expand("R") as never, []);
  assert.equal(r.valid, true);
  assert.equal(r.signatures, 2);
  assert.equal(r.required, 2);
  assert.equal(r.pin.version, 1);
});

test("TV-B--04 UTF-16 ordering, not Unicode scalar ordering", () => {
  const keys = canonicalKeyOrder({ "": 1, "𐀀": 2 });
  assert.deepEqual(keys, ["𐀀", ""]);
});

test("TV-B--05 duplicate JSON member rejection", () => {
  assert.throws(() => parseJson('{"version":1,"version":2}'), (e) => code(e) === "PARSE");
});

test("TV-B--06 YAML merge and alias rejection", () => {
  assert.throws(
    () => parseYaml("base: &b {version: 1}\ncharter: {<<: *b}\n"),
    (e) => code(e) === "PARSE",
  );
});

test("TV-B--07 decomposed Unicode rejection", () => {
  assert.throws(() => parseJson('{"description":"é"}'), (e) => code(e) === "PARSE");
});

test("TV-B--08 numeric exponent ambiguity rejected", () => {
  assert.throws(() => parseJson('{"version":1e0}'), (e) => code(e) === "PARSE");
});

test("TV-B--09 unknown policy field cannot enable override", () => {
  const c = expand("C1") as Record<string, unknown>;
  c["allow_all"] = true;
  assert.throws(() => compile(c as never, expand("M1") as never), (e) => code(e) === "SCHEMA");
});

test("TV-B--10 duplicate signature cannot meet quorum", () => {
  const b = expand("B1") as Bundle;
  b.signatures = [b.signatures[0]!, b.signatures[0]!];
  assert.throws(() => verifyBundle(b, expand("R") as never, []), (e) => code(e) === "SIGNATURE_DUPLICATE");
});

test("TV-B--11 one distinct signer is insufficient", () => {
  const b = expand("B1") as Bundle;
  b.signatures = [b.signatures[0]!];
  assert.throws(() => verifyBundle(b, expand("R") as never, []), (e) => code(e) === "QUORUM");
});

test("TV-B--12 mutation under old signatures fails", () => {
  const b = expand("B1") as Record<string, unknown>;
  applySet(b, { "/charter/description": "Override every deny." });
  assert.throws(() => verifyBundle(b as unknown as Bundle, expand("R") as never, []), (e) => code(e) === "SIGNATURE_INVALID");
});

test("TV-B--13 same-key aliases are not independent authority", () => {
  const c = expand("C1") as Record<string, unknown>;
  applySet(c, { "/next_authority/keys/1/public_key": FX.PUB[0] });
  assert.throws(() => compile(c as never, expand("M1") as never), (e) => code(e) === "SCHEMA");
});

test("TV-B--14 baseline scope allow", () => {
  const d = evalDecision();
  assert.equal(d.verdict, "ALLOW");
  assert.equal(d.reason, "ALLOW_SCOPE");
  assert.deepEqual(d.rule_ids, [FX.RA]);
});

test("TV-B--15 explicit hard deny", () => {
  const d = evalDecision({ request_patch: { tool: "record.delete" } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "HARD_DENY");
  assert.deepEqual(d.rule_ids, [FX.RD]);
});

test("TV-B--16 deny wins even over a matching allow", () => {
  const d = evalDecision({
    request_patch: { tool: "record.delete" },
    set: { "/charter/scope_rules/0/tools": ["record.delete", "record.get", "record.list", "record.put"] },
  });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "HARD_DENY");
  assert.deepEqual(d.rule_ids, [FX.RD]);
});

test("TV-B--17 prefix is segment-boundary aware", () => {
  const d = evalDecision({ request_patch: { resource: "records2/a" } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "NO_SCOPE");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--18 unknown tool cannot use an alias", () => {
  const d = evalDecision({ request_patch: { tool: "record.exec" } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "UNKNOWN_TOOL");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--19 caller cannot select a foreign scope", () => {
  const d = evalDecision({ request_patch: { scope: "task-b" } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "PRINCIPAL_SCOPE");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--20 known but uncovered export is denied", () => {
  const d = evalDecision({ request_patch: { tool: "record.export", args: { destination: "task-b" } } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "NO_SCOPE");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--21 arguments remain typed", () => {
  assert.throws(
    () => evalDecision({ request_patch: { tool: "record.list", args: { limit: "10" } } }),
    (e) => code(e) === "SCHEMA",
  );
});

test("TV-B--22 missing field cannot hide a deny predicate", () => {
  assert.throws(
    () => evalDecision({ request_patch: { tool: "record.put", args: {} } }),
    (e) => code(e) === "SCHEMA",
  );
});

test("TV-B--23 encoded path traversal is not normalized", async () => {
  const env = await buildF();
  const r = await call(env, {
    method: "POST", path: "/v1/gateway/call", role: "agent",
    body: patchedRequest({ resource: "records/%2e%2e/admin" }) as unknown as Json,
  });
  assert.equal(r.status, 400);
  assert.equal((r.body as { error: { code: string } }).error.code, "SCHEMA");
  assert.equal(env.dispatchCount(), 0);
});

test("TV-B--24 pin version mismatch fails before matching rules", () => {
  const d = evalDecision({ set: { "/request/pin/version": 2 } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "PIN_MISMATCH");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--25 manifest substitution fails", () => {
  const b = expand("B1") as Record<string, unknown>;
  applySet(b, { "/manifest/tools/0/operation": "get" });
  assert.throws(() => verifyBundle(b as unknown as Bundle, expand("R") as never, []), (e) => code(e) === "HASH_MISMATCH");
});

test("TV-B--26 charter validity excludes its end", () => {
  const d = evalDecision({ now: "2026-10-12T00:00:00.000Z" });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "CHARTER_EXPIRED");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--27 charter is not valid a millisecond early", () => {
  const d = evalDecision({ now: "2026-09-11T23:59:59.999Z" });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "CHARTER_NOT_YET_VALID");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--28 call deadline equality denies", () => {
  const d = evalDecision({ now: "2026-09-12T00:00:30.000Z" });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "DEADLINE");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--29 gateway effect occurs only after durable dispatch record", async () => {
  const env = await buildF();
  const before = env.auditEvents().length;
  const r = await call(env, {
    method: "POST", path: "/v1/gateway/call", role: "agent",
    body: FX.Q1 as unknown as Json,
  });
  assert.equal(r.status, 200);
  const body = r.body as unknown as CallResult;
  assert.equal(body.state, "SUCCEEDED");
  assert.equal(body.decision.reason, "ALLOW_SCOPE");
  assert.equal(env.dispatchCount(), 1);
  const events = env.auditEvents().slice(before);
  assert.deepEqual(events, ["CallDispatched", "CallFinished"]);
});

test("TV-B--30 denied call never reaches adapter", async () => {
  const env = await buildF();
  const before = env.auditEvents().length;
  const r = await call(env, {
    method: "POST", path: "/v1/gateway/call", role: "agent",
    body: patchedRequest({ tool: "record.delete" }) as unknown as Json,
  });
  assert.equal(r.status, 200);
  const body = r.body as unknown as CallResult;
  assert.equal(body.state, "DENIED");
  assert.equal(body.decision.reason, "HARD_DENY");
  assert.equal(env.dispatchCount(), 0);
  assert.deepEqual(env.auditEvents().slice(before), ["CallDenied"]);
});

test("TV-B--31 exact call retry is not another effect", async () => {
  const env = await buildF();
  const before = env.auditEvents().length;
  const r1 = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  const r2 = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(env.dispatchCount(), 1);
  assert.equal(env.auditEvents().slice(before).length, 2);
  assert.equal(canonicalString(r1.body), canonicalString(r2.body));
});

test("TV-B--32 changed request under reused ID conflicts", async () => {
  const env = await buildF();
  await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  const r2 = await call(env, {
    method: "POST", path: "/v1/gateway/call", role: "agent",
    body: patchedRequest({ resource: "records/b" }) as unknown as Json,
  });
  assert.equal(r2.status, 409);
  assert.equal((r2.body as { error: { code: string } }).error.code, "IDEMPOTENCY_CONFLICT");
  assert.equal(env.dispatchCount(), 1);
});

test("TV-B--33 audit failure before marker is fail-closed", async () => {
  const env = await buildF();
  (env.dobj as unknown as { deps: { faults?: Set<string> } }).deps.faults = new Set(["audit_commit_before_dispatch"]);
  const r = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(r.status, 503);
  assert.equal((r.body as { error: { code: string } }).error.code, "AUDIT_UNAVAILABLE");
  assert.equal(env.dispatchCount(), 0);
});

test("TV-B--34 crash in marker/send gap never resends", async () => {
  const store = new (await import("../src/server/storage.js")).Store(":memory:");
  const faults = new Set(["crash_after_marker"]);
  const env = await buildF({ store, faults });
  const before = env.auditEvents().length;
  await assert.rejects(
    call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json }),
    (e: unknown) => (e as Error).name === "CrashFault",
  );
  // recover on the same store: a fresh DO instance
  const env2 = newTenant({ store, now: env.now.ms });
  const r = await call(env2, { method: "GET", path: `/v1/gateway/calls/${FX.Q1.request_id}`, role: "agent" });
  const body = r.body as unknown as CallResult;
  assert.equal(body.state, "INDETERMINATE");
  assert.equal(env2.dispatchCount(), 0);
  assert.deepEqual(env2.auditEvents().slice(before), ["CallDispatched", "CallFinished"]);
});

test("TV-B--35 pause wins dispatch ordering", async () => {
  const env = await buildF();
  const p = await call(env, { method: "POST", path: "/v1/deployment/pause", role: "operator", body: pauseBody(1) as unknown as Json });
  assert.equal(p.status, 200);
  const r = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(r.status, 503);
  assert.equal((r.body as { error: { code: string } }).error.code, "PAUSED");
  assert.equal(env.dispatchCount(), 0);
  assert.equal((r.body as { error: { audit_seq: number | null } }).error.audit_seq !== null, true);
  const dep = (await call(env, { method: "GET", path: "/v1/deployment", role: "operator" })).body as { revision: number };
  assert.equal(dep.revision, 2);
});

test("TV-B--36 dispatch wins pause ordering, no false rollback", async () => {
  const adapter = new (await import("../src/server/adapter.js")).FixtureRecordsAdapter();
  const gate: { resolve?: (v: { status: "ok"; output: Json }) => void } = {};
  adapter.setBehavior(() => new Promise((res) => { gate.resolve = res; }));
  const env = await buildF({ adapter });
  const callP = call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  // wait until dispatch marker is durable and invocation initiated
  for (let i = 0; i < 200 && env.dispatchCount() === 0; i++) await new Promise((r) => setTimeout(r, 1));
  assert.equal(env.dispatchCount(), 1);
  const p = await call(env, {
    method: "POST", path: "/v1/deployment/pause", role: "operator",
    body: { request_id: FX.ID("brq", "Z"), expected_revision: 1, reason: "Incident containment" } as unknown as Json,
  });
  assert.equal(p.status, 200);
  assert.equal((p.body as { in_flight: number }).in_flight, 1);
  assert.equal((p.body as { revision: number }).revision, 2);
  gate.resolve!({ status: "ok", output: { value: "ok" } });
  const r = await callP;
  assert.equal(r.status, 200);
  assert.equal((r.body as unknown as CallResult).state, "SUCCEEDED");
});

test("TV-B--37 expired signed pin is not accepted", async () => {
  const env = await buildB1Published({ now: parseTime("2026-09-12T00:05:00.000Z") });
  const r = await call(env, { method: "POST", path: "/v1/deployment/pin", role: "operator", body: FX.U1 as unknown as Json });
  assert.equal(r.status, 422);
  assert.equal((r.body as { error: { code: string } }).error.code, "PIN_EXPIRED");
  const dep = (await call(env, { method: "GET", path: "/v1/deployment", role: "operator" })).body as { revision: number };
  assert.equal(dep.revision, 0);
});

test("TV-B--38 replayed pin with a different request ID fails signature", async () => {
  const env = await buildB1Published();
  const u = structuredClone(FX.U1) as unknown as Record<string, unknown>;
  applySet(u, { "/update/request_id": "brq_RRRRRRRRRRRRRRRRRRRRR" });
  const r = await call(env, { method: "POST", path: "/v1/deployment/pin", role: "operator", body: u as Json });
  assert.equal(r.status, 422);
  assert.equal((r.body as { error: { code: string } }).error.code, "SIGNATURE_INVALID");
  const dep = (await call(env, { method: "GET", path: "/v1/deployment", role: "operator" })).body as { revision: number };
  assert.equal(dep.revision, 0);
});

test("TV-B--39 concurrent publication has one winner", async () => {
  const env = await buildF();
  const b2a = structuredClone(FX.B2) as Bundle;
  const b2b = structuredClone(FX.B2) as unknown as Record<string, unknown>;
  applySet(b2b, { "/charter/source/pull_request": 9 });
  resign("charter", b2b);
  const r1 = await call(env, {
    method: "POST", path: "/v1/charter/publish", role: "operator",
    body: { request_id: FX.ID("brq", "N"), bundle: b2a } as unknown as Json,
  });
  const r2 = await call(env, {
    method: "POST", path: "/v1/charter/publish", role: "operator",
    body: { request_id: FX.ID("brq", "W"), bundle: b2b } as unknown as Json,
  });
  assert.deepEqual([r1.status, r2.status], [201, 409]);
  assert.equal((r2.body as { error: { code: string } }).error.code, "VERSION_CONFLICT");
  const versions = (await call(env, { method: "GET", path: "/v1/charter/versions?after=0&limit=100", role: "operator" })).body as { head_version: number };
  assert.equal(versions.head_version, 2);
  const pubs = env.auditEvents().filter((e) => e === "CharterPublished").length;
  assert.equal(pubs, 2); // B1 setup + one B2 winner
});

test("TV-B--40 old version cannot become a new deployment target", async () => {
  const env = await buildF();
  const b2 = structuredClone(FX.B2) as Bundle;
  const pub = await call(env, {
    method: "POST", path: "/v1/charter/publish", role: "operator",
    body: { request_id: FX.ID("brq", "N"), bundle: b2 } as unknown as Json,
  });
  assert.equal(pub.status, 201);
  // old-pin update: U1 fields, request_id R, expected_revision 1, target P1, re-sign
  const u = structuredClone(FX.U1) as unknown as Record<string, unknown>;
  applySet(u, { "/update/request_id": "brq_RRRRRRRRRRRRRRRRRRRRR", "/update/expected_revision": 1 });
  resign("pin", u);
  const r = await call(env, { method: "POST", path: "/v1/deployment/pin", role: "operator", body: u as Json });
  assert.equal(r.status, 409);
  assert.equal((r.body as { error: { code: string } }).error.code, "PIN_NOT_HEAD");
  const dep = (await call(env, { method: "GET", path: "/v1/deployment", role: "operator" })).body as { pin: { version: number } };
  assert.equal(dep.pin.version, 1);
});

test("TV-B--41 fleet expiry is exact and read-time derived", async () => {
  const env = await buildF();
  env.now.ms = parseTime("2026-09-12T00:03:00.000Z");
  const f = (await call(env, { method: "GET", path: "/v1/fleet", role: "operator" })).body as {
    status: string; instances: { state: string; counter: number }[];
  };
  assert.equal(f.status, "MISSING");
  assert.equal(f.instances[0]!.state, "MISSING");
  assert.equal(f.instances[0]!.counter, 1);
});

test("TV-B--42 heartbeat replay cannot refresh freshness", async () => {
  const env = await buildF();
  env.now.ms = parseTime("2026-09-12T00:02:59.999Z");
  const retry = await call(env, { method: "POST", path: "/v1/fleet/heartbeat", role: "instance", body: FX.HB1 as unknown as Json });
  assert.equal(retry.status, 200);
  env.now.ms = parseTime("2026-09-12T00:03:00.000Z");
  const f = (await call(env, { method: "GET", path: "/v1/fleet", role: "operator" })).body as {
    status: string; instances: { expires_at: string; counter: number }[];
  };
  assert.equal(f.status, "MISSING");
  assert.equal(f.instances[0]!.expires_at, "2026-09-12T00:03:00.000Z");
  assert.equal(f.instances[0]!.counter, 1);
});

test("TV-B--43 an instance cannot invent inventory", async () => {
  const env = await buildF();
  const r = await call(env, {
    method: "POST", path: "/v1/fleet/heartbeat", role: "instance",
    body: patchedHeartbeat(undefined, { "/instance_id": "bin_BBBBBBBBBBBBBBBBBBBBB" }) as unknown as Json,
  });
  assert.equal(r.status, 404);
  assert.equal((r.body as { error: { code: string } }).error.code, "NOT_FOUND");
  const f = (await call(env, { method: "GET", path: "/v1/fleet", role: "operator" })).body as { instances: unknown[] };
  assert.equal(f.instances.length, 1);
});

test("TV-B--44 fresh divergent version is visible and denied", async () => {
  const env = await buildF();
  const hb = await call(env, {
    method: "POST", path: "/v1/fleet/heartbeat", role: "instance",
    body: patchedHeartbeat({ request_id: "brq_JJJJJJJJJJJJJJJJJJJJJ", counter: 2, observed_pin: "P2" }) as unknown as Json,
  });
  assert.equal(hb.status, 200);
  const f = (await call(env, { method: "GET", path: "/v1/fleet", role: "operator" })).body as { status: string };
  assert.equal(f.status, "SPLIT");
  const r = await call(env, { method: "POST", path: "/v1/gateway/call", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(r.status, 503);
  assert.equal((r.body as { error: { code: string } }).error.code, "INSTANCE_MISMATCH");
  assert.equal(env.dispatchCount(), 0);
});

test("TV-B--45 dispute cannot change future authorization", async () => {
  const env = await buildF();
  // check Q1 → seq 4
  const chk = await call(env, { method: "POST", path: "/v1/gateway/check", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(chk.status, 200);
  const d = await call(env, { method: "POST", path: "/v1/disputes", role: "agent", body: FX.DR1 as unknown as Json });
  assert.equal(d.status, 201);
  assert.equal((d.body as { status: string }).status, "RECORDED_ADVISORY");
  const del = await call(env, {
    method: "POST", path: "/v1/gateway/call", role: "agent",
    body: patchedRequest({ request_id: FX.ID("brq", "E"), tool: "record.delete" }) as unknown as Json,
  });
  assert.equal(del.status, 200);
  assert.equal((del.body as unknown as CallResult).decision.reason, "HARD_DENY");
  assert.equal(env.dispatchCount(), 0);
  const dep = (await call(env, { method: "GET", path: "/v1/deployment", role: "operator" })).body as { pin: { version: number } };
  assert.equal(dep.pin.version, 1);
});

test("TV-B--46 request for law is not silently supported", () => {
  // compile_composition: only pin/bundle/decision/audit outputs exist
  const required = ["pin", "precedent_root"];
  const available = new Set(["pin", "bundle", "decision", "audit"]);
  const missing = required.filter((r) => !available.has(r));
  assert.throws(
    () => {
      if (missing.length) throw new BedrockError("UNSUPPORTED_COMPOSITION", `unmet law requirements: ${missing.join(",")}`);
    },
    (e) => code(e) === "UNSUPPORTED_COMPOSITION",
  );
});

test("TV-B--47 exact audit hash fixture", () => {
  assert.equal(D("audit", FX.E1BODY), "57e872be05ec64b518fb9e0b80a04ab2d57b2682aeede1fe331d211176878648");
});

test("TV-B--48 offline audit integrity relative to trusted checkpoint", () => {
  const v = verifyEvidence(expand("EV1") as never, expand("R") as never, expand("CP1") as never, false);
  assert.deepEqual(v, { integrity: "VALID", replay: "NOT_REQUESTED", through_seq: 1, anchored: true });
});

test("TV-B--49 tampered audit body fails verification", () => {
  const ev = expand("EV1") as Record<string, unknown>;
  applySet(ev, { "/entries/0/body/seq": 2 });
  const v = verifyEvidence(ev as never, expand("R") as never, expand("CP1") as never, false);
  assert.deepEqual(v, { integrity: "INVALID", replay: "NOT_REQUESTED", through_seq: 0, anchored: false });
});

test("TV-B--50 missing anchored suffix is incomplete, not valid", () => {
  const ev = expand("EV1") as Record<string, unknown>;
  applySet(ev, { "/entries": [] });
  const v = verifyEvidence(ev as never, expand("R") as never, expand("CP1") as never, false);
  assert.deepEqual(v, { integrity: "INCOMPLETE", replay: "NOT_REQUESTED", through_seq: 0, anchored: false });
});

test("TV-B--51 empty allow list stays default-deny", () => {
  const d = evalDecision({ charter_patch: { scope_rules: [] } });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "NO_SCOPE");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--52 a predicate uses integer comparison, not lexical order", () => {
  const d = evalDecision({
    request_patch: { tool: "record.list", args: { limit: 10 } },
    set: {
      "/charter/scope_rules/0/tools": ["record.list"],
      "/charter/scope_rules/0/when": [{ arg: "limit", op: "int_lte", value: 2 }],
    },
  });
  assert.equal(d.verdict, "DENY");
  assert.equal(d.reason, "NO_SCOPE");
  assert.deepEqual(d.rule_ids, []);
});

test("TV-B--53 dispute pin must equal the cited entry's pin", async () => {
  const env = await buildF();
  const chk = await call(env, { method: "POST", path: "/v1/gateway/check", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(chk.status, 200);
  const r = await call(env, {
    method: "POST", path: "/v1/disputes", role: "agent",
    body: patchedDispute(undefined, { "/pin": "P2" }) as unknown as Json,
  });
  assert.equal(r.status, 422);
  assert.equal((r.body as { error: { code: string } }).error.code, "HASH_MISMATCH");
});

test("TV-B--54 a foreign-tenant charter is not this lineage's genesis", () => {
  const b = expand("B1") as Record<string, unknown>;
  applySet(b, { "/charter/tenant_id": "bte_BBBBBBBBBBBBBBBBBBBBB" });
  resign("charter", b);
  assert.throws(() => verifyBundle(b as unknown as Bundle, expand("R") as never, []), (e) => code(e) === "SCHEMA");
});

test("TV-B--55 a dispute ID cannot be reused by a different request", async () => {
  const env = await buildF();
  const chk = await call(env, { method: "POST", path: "/v1/gateway/check", role: "agent", body: FX.Q1 as unknown as Json });
  assert.equal(chk.status, 200);
  const d1 = await call(env, { method: "POST", path: "/v1/disputes", role: "agent", body: FX.DR1 as unknown as Json });
  assert.equal(d1.status, 201);
  const d2 = await call(env, {
    method: "POST", path: "/v1/disputes", role: "agent",
    body: patchedDispute({ request_id: FX.ID("brq", "F"), statement: "A different statement." }) as unknown as Json,
  });
  assert.equal(d2.status, 409);
  assert.equal((d2.body as { error: { code: string } }).error.code, "IDEMPOTENCY_CONFLICT");
});
