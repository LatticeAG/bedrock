#!/usr/bin/env node
/**
 * bedrock CLI (spec §8.1) — 23 commands, canonical JSON + LF on stdout,
 * diagnostics on stderr, exit codes per the §8.1 table.
 */
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { BedrockError, exitCodeFor, type ErrorCode } from "./errors.js";
import { canonicalString, parseJsonBytes, type Json } from "./canon.js";
import { parseYaml } from "./yaml.js";
import { D, S, sha256Hex, hexDecode, ed25519Sign, b64urlEncode, ed25519PublicKey } from "./crypto.js";
import {
  vBundle, vCharter, vManifest, vCallRequest, vDisputeRequest, vHeartbeat,
  vSignedPinUpdate, vDetached, vPinUpdate, vRootFile, vEvidence,
} from "./schema.js";
import { compile } from "./compiler.js";
import { verifyBundle, checkSignatures, canonicalEqual } from "./bundle.js";
import { verifyEvidence } from "./evidence.js";
import { semanticDiff } from "./diff.js";
import { BedrockClient, ApiError } from "./client.js";
import { loadConfig, loadAuthRecords, loadResponseKeys, loadAuditSeed, clientCredential, resolveEnvRef } from "./config.js";
import { Store } from "./server/storage.js";
import { BedrockTenantDO } from "./server/tenant.js";
import { LocalEmulator } from "./server/http.js";
import { MemoryRecordsAdapter } from "./server/adapter.js";
import type {
  Bundle, Charter, Detached, DisputeRequest, Heartbeat, Manifest, Pin,
  PinUpdate, RootFile, SignedPinUpdate, Warning, CallRequest,
} from "./types.js";
import { formatTime, parseTime } from "./time.js";

const VERSION = "0.1.0";

interface Args {
  positional: string[];
  flags: Map<string, string | true>;
  repeated: Map<string, string[]>;
}

const REPEATABLE = new Set(["signature", "predecessor"]);
const BOOL_FLAGS = new Set(["json", "replace", "local", "replay", "help", "version"]);

function parseArgs(argv: string[]): Args {
  const positional: string[] = [];
  const flags = new Map<string, string | true>();
  const repeated = new Map<string, string[]>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      let name = a.slice(2);
      let val: string | true = true;
      if (eq !== -1) {
        name = a.slice(2, eq);
        val = a.slice(eq + 1);
      } else if (!BOOL_FLAGS.has(name) && i + 1 < argv.length && !argv[i + 1]!.startsWith("--")) {
        val = argv[++i]!;
      }
      if (REPEATABLE.has(name)) {
        repeated.set(name, [...(repeated.get(name) ?? []), val as string]);
      } else {
        flags.set(name, val);
      }
    } else {
      positional.push(a);
    }
  }
  return { positional, flags, repeated };
}

function flag(args: Args, name: string): string | undefined {
  const v = args.flags.get(name);
  return v === true ? undefined : v;
}
function flagBool(args: Args, name: string): boolean {
  return args.flags.has(name);
}
function flagInt(args: Args, name: string, dflt?: number): number {
  const v = args.flags.get(name);
  if (v === undefined) {
    if (dflt !== undefined) return dflt;
    throw new BedrockError("SCHEMA", `missing required --${name}`);
  }
  if (v === true || !/^(0|[1-9][0-9]*)$/.test(v)) {
    throw new BedrockError("SCHEMA", `--${name} must be a canonical unsigned integer`);
  }
  const n = Number(v);
  if (!Number.isSafeInteger(n)) throw new BedrockError("SCHEMA", `--${name} out of range`);
  return n;
}
function need(args: Args, name: string): string {
  const v = flag(args, name);
  if (v === undefined) throw new BedrockError("SCHEMA", `missing required --${name}`);
  return v;
}
function pos(args: Args, i: number, name: string): string {
  const p = args.positional[i];
  if (p === undefined) throw new BedrockError("SCHEMA", `missing argument ${name}`);
  return p;
}

function out(v: Json): void {
  process.stdout.write(canonicalString(v) + "\n");
}
function err(s: string): void {
  process.stderr.write(s + "\n");
}

function readJsonFile(path: string): Json {
  try {
    return parseJsonBytes(new Uint8Array(readFileSync(path)));
  } catch (e) {
    if (e instanceof BedrockError) throw e;
    throw new BedrockError("PARSE", `cannot read ${path}`);
  }
}
function readCharterFile(path: string): Charter {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new BedrockError("PARSE", `cannot read ${path}`);
  }
  const trimmed = raw.trimStart();
  if (trimmed.startsWith("{")) return vCharter(parseJsonBytes(new Uint8Array(readFileSync(path))));
  return vCharter(parseYaml(raw));
}
function writeOut(path: string, bytes: Uint8Array, replace: boolean): void {
  if (existsSync(path) && !replace) {
    throw new BedrockError("SCHEMA", `${path} exists; pass --replace`);
  }
  writeFileSync(path, bytes);
}

function makeClient(args: Args): { client: BedrockClient; loaded: ReturnType<typeof loadConfig> } {
  const cfgPath = flag(args, "config") ?? "./bedrock.yaml";
  const loaded = loadConfig(cfgPath);
  const credential = clientCredential(loaded.config);
  const timeoutMs = flagInt(args, "timeout-ms", 10000);
  if (timeoutMs < 1 || timeoutMs > 60000) {
    throw new BedrockError("SCHEMA", "--timeout-ms outside [1,60000]");
  }
  return {
    client: new BedrockClient({ endpoint: loaded.config.endpoint, credential, timeoutMs }),
    loaded,
  };
}

function loadKeyFromRef(ref: string): Uint8Array {
  // key refs are env: handles holding a 64-hex seed
  const hex = resolveEnvRef(ref).trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new BedrockError("SCHEMA", "key material must be 64 lowercase hex");
  return Buffer.from(hex, "hex");
}

function warningsFor(c: Charter): Warning[] {
  const w: Warning[] = [];
  if (c.scope_rules.length === 0) w.push("NO_ALLOW_RULES");
  if (c.next_authority.threshold === 1) w.push("SINGLE_SIGNER");
  if (parseTime(c.not_after) - Date.now() <= 24 * 3600 * 1000) w.push("EXPIRY_WITHIN_24H");
  return w.sort();
}

// ---------------------------------------------------------------------------

async function cmdCharterLint(args: Args): Promise<number> {
  const file = pos(args, 0, "FILE");
  const charter = readCharterFile(file);
  const manifest = vManifest(readJsonFile(need(args, "manifest")));
  const root = vRootFile(readJsonFile(need(args, "root")));
  const c = compile(charter, manifest);
  if (charter.tenant_id !== root.tenant_id || charter.charter_id !== root.charter_id || manifest.gateway_id !== root.gateway_id) {
    throw new BedrockError("SCHEMA", "charter/manifest lineage does not match root");
  }
  const pred = flag(args, "predecessor");
  if (pred !== undefined) {
    const p = vBundle(readJsonFile(pred));
    if (charter.previous_hash !== D("charter", p.charter)) {
      throw new BedrockError("HASH_MISMATCH", "previous_hash does not match predecessor");
    }
    if (charter.version !== p.charter.version + 1) {
      throw new BedrockError("VERSION_CONFLICT", "version must be predecessor + 1");
    }
  }
  out({ valid: true, charter_hash: c.charter_hash, manifest_hash: c.manifest_hash, warnings: warningsFor(charter) } as unknown as Json);
  return 0;
}

async function cmdCharterCanonicalize(args: Args): Promise<number> {
  const file = pos(args, 0, "FILE");
  const charter = readCharterFile(file);
  const bytes = new TextEncoder().encode(canonicalString(charter as unknown as Json));
  const outPath = need(args, "out");
  writeOut(outPath, bytes, flagBool(args, "replace"));
  out({ charter_hash: D("charter", charter), bytes: bytes.length, out: outPath } as unknown as Json);
  return 0;
}

async function cmdCharterDiff(args: Args): Promise<number> {
  const oldPath = pos(args, 0, "OLD");
  const newPath = pos(args, 1, "NEW");
  const manifestPath = need(args, "manifest");
  const manifest = vManifest(readJsonFile(manifestPath));
  const oldC = readCharterFile(oldPath);
  const newC = readCharterFile(newPath);
  compile(oldC, manifest);
  compile(newC, manifest);
  const changes = semanticDiff(oldC as unknown as Json, newC as unknown as Json);
  const authorityChanged = !canonicalEqual(oldC.next_authority, newC.next_authority);
  out({
    old_hash: D("charter", oldC), new_hash: D("charter", newC),
    changes: changes as unknown as Json, authority_changed: authorityChanged,
  } as unknown as Json);
  return 0;
}

async function cmdCharterSign(args: Args): Promise<number> {
  const file = pos(args, 0, "FILE");
  const charter = readCharterFile(file);
  const manifest = vManifest(readJsonFile(need(args, "manifest")));
  compile(charter, manifest);
  const keyId = need(args, "key-id");
  const seed = loadKeyFromRef(need(args, "key-ref"));
  const msg = S("charter", charter as unknown as Json);
  const sig = ed25519Sign(seed, msg);
  const detached: Detached = { key_id: keyId, signature: b64urlEncode(sig) };
  const outPath = need(args, "out");
  writeOut(outPath, new TextEncoder().encode(canonicalString(detached as unknown as Json)), flagBool(args, "replace"));
  out({ charter_hash: D("charter", charter), key_id: keyId, out: outPath } as unknown as Json);
  return 0;
}



async function cmdCharterBundle(args: Args): Promise<number> {
  const file = pos(args, 0, "FILE");
  const charter = readCharterFile(file);
  const manifest = vManifest(readJsonFile(need(args, "manifest")));
  const root = vRootFile(readJsonFile(need(args, "root")));
  const sigFiles = args.repeated.get("signature") ?? [];
  if (sigFiles.length === 0) throw new BedrockError("SCHEMA", "at least one --signature is required");
  const sigs: Detached[] = sigFiles.map((f) => vDetached(readJsonFile(f)));
  const bundle: Bundle = { charter, manifest, signatures: sigs };
  const preds = (args.repeated.get("predecessor") ?? []).map((f) => vBundle(readJsonFile(f)));
  verifyBundle(bundle, root, preds);
  const outPath = need(args, "out");
  writeOut(outPath, new TextEncoder().encode(canonicalString(bundle as unknown as Json)), flagBool(args, "replace"));
  out({ charter_hash: D("charter", charter), signatures: sigs.length, out: outPath } as unknown as Json);
  return 0;
}

async function cmdCharterVerify(args: Args): Promise<number> {
  const file = pos(args, 0, "BUNDLE");
  const bundle = vBundle(readJsonFile(file));
  const root = vRootFile(readJsonFile(need(args, "root")));
  const preds = (args.repeated.get("predecessor") ?? []).map((f) => vBundle(readJsonFile(f)));
  const r = verifyBundle(bundle, root, preds);
  out({ valid: true, pin: r.pin, signatures: r.signatures, required: r.required } as unknown as Json);
  return 0;
}

async function cmdCharterPublish(args: Args): Promise<number> {
  const file = pos(args, 0, "BUNDLE");
  const bundle = vBundle(readJsonFile(file));
  const requestId = need(args, "request-id");
  const { client } = makeClient(args);
  const r = await client.charterPublish(requestId, bundle);
  out(r);
  return 0;
}

async function cmdCharterFetch(args: Args): Promise<number> {
  const vRaw = pos(args, 0, "VERSION");
  if (!/^[1-9][0-9]*$/.test(vRaw)) throw new BedrockError("SCHEMA", "VERSION must be canonical positive decimal");
  const v = Number(vRaw);
  const { client, loaded } = makeClient(args);
  const bundle = await client.charterVersion(v);
  // local verification against configured root and stored history
  const preds: Bundle[] = [];
  for (let i = 1; i < bundle.charter.version; i++) {
    preds.push(await client.charterVersion(i));
  }
  const r = verifyBundle(bundle, loaded.root, preds);
  const outPath = need(args, "out");
  writeOut(outPath, new TextEncoder().encode(canonicalString(bundle as unknown as Json)), flagBool(args, "replace"));
  out({ pin: r.pin, out: outPath } as unknown as Json);
  return 0;
}

async function cmdPinSign(args: Args): Promise<number> {
  const bundle = vBundle(readJsonFile(need(args, "bundle")));
  const cfg = loadConfig(flag(args, "config") ?? "./bedrock.yaml").config;
  const expectedRevision = flagInt(args, "expected-revision");
  const requestId = need(args, "request-id");
  const expiresAt = need(args, "expires-at");
  const target: Pin = {
    charter_id: bundle.charter.charter_id, version: bundle.charter.version,
    charter_hash: D("charter", bundle.charter), manifest_hash: D("manifest", bundle.manifest),
    engine: bundle.charter.engine,
  };
  const update: PinUpdate = {
    schema: "bedrock.pin/1", tenant_id: cfg.tenant_id, gateway_id: cfg.gateway_id,
    request_id: requestId, expected_revision: expectedRevision,
    target, expires_at: expiresAt,
  };
  vPinUpdate(update);
  const keyId = need(args, "key-id");
  const seed = loadKeyFromRef(need(args, "key-ref"));
  const sig: Detached = { key_id: keyId, signature: b64urlEncode(ed25519Sign(seed, S("pin", update as unknown as Json))) };
  const share = { update, signature: sig };
  const outPath = need(args, "out");
  writeOut(outPath, new TextEncoder().encode(canonicalString(share as unknown as Json)), flagBool(args, "replace"));
  out({ charter_hash: target.charter_hash, key_id: keyId, out: outPath } as unknown as Json);
  return 0;
}

async function cmdPinActivate(args: Args): Promise<number> {
  const file = pos(args, 0, "UPDATE");
  const u = vSignedPinUpdate(readJsonFile(file));
  const { client } = makeClient(args);
  const r = await client.pin(u);
  out(r);
  return 0;
}

async function cmdGatewayPause(args: Args): Promise<number> {
  const { client } = makeClient(args);
  const r = await client.pause({
    request_id: need(args, "request-id"),
    expected_revision: flagInt(args, "expected-revision"),
    reason: need(args, "reason"),
  });
  out(r);
  return 0;
}

async function cmdGatewayStatus(args: Args): Promise<number> {
  const { client } = makeClient(args);
  const deployment = await client.deployment();
  let readiness: Json = null;
  try {
    readiness = await client.readyz();
  } catch (e) {
    if (e instanceof ApiError) readiness = { ready: false, error: e.code } as unknown as Json;
    else throw e;
  }
  out({ deployment: deployment as unknown as Json, readiness } as unknown as Json);
  return 0;
}

async function cmdGatewayCheck(args: Args): Promise<number> {
  const req = vCallRequest(readJsonFile(pos(args, 0, "REQUEST")));
  const { client } = makeClient(args);
  const r = await client.check(req);
  out(r as unknown as Json);
  return r.decision.verdict === "ALLOW" ? 0 : 3;
}

async function cmdGatewayCall(args: Args): Promise<number> {
  const req = vCallRequest(readJsonFile(pos(args, 0, "REQUEST")));
  const { client } = makeClient(args);
  const { status, result } = await client.call(req);
  out(result as unknown as Json);
  switch (result.state) {
    case "SUCCEEDED": return 0;
    case "DENIED": return 3;
    case "DISPATCHED":
    case "INDETERMINATE": return 8;
    case "FAILED": return 9;
  }
  void status;
  return 0;
}

async function cmdGatewayResult(args: Args): Promise<number> {
  const id = pos(args, 0, "ID");
  const { client } = makeClient(args);
  const { result } = await client.callResult(id);
  out(result as unknown as Json);
  switch (result.state) {
    case "SUCCEEDED": return 0;
    case "DENIED": return 3;
    case "DISPATCHED":
    case "INDETERMINATE": return 8;
    case "FAILED": return 9;
  }
  return 0;
}

async function cmdDisputeRecord(args: Args): Promise<number> {
  const req = vDisputeRequest(readJsonFile(pos(args, 0, "FILE")));
  const { client } = makeClient(args);
  const r = await client.dispute(req);
  out(r as unknown as Json);
  return 0;
}

async function cmdDisputeList(args: Args): Promise<number> {
  const { client } = makeClient(args);
  const r = await client.disputes(flagInt(args, "after-seq", 0), flagInt(args, "limit", 100));
  out(r);
  return 0;
}

async function cmdFleetStatus(args: Args): Promise<number> {
  const { client } = makeClient(args);
  const watchMs = args.flags.has("watch-ms") ? flagInt(args, "watch-ms") : null;
  if (watchMs !== null && (watchMs < 1000 || watchMs > 60000)) {
    throw new BedrockError("SCHEMA", "--watch-ms outside [1000,60000]");
  }
  const once = async () => {
    const fleet = await client.fleet();
    return fleet;
  };
  if (watchMs === null) {
    const fleet = await once();
    out(fleet as unknown as Json);
    return fleet.status === "HEALTHY" ? 0 : 3;
  }
  // watch mode: canonical JSONL snapshots until interrupted
  for (;;) {
    const fleet = await once();
    process.stdout.write(canonicalString(fleet as unknown as Json) + "\n");
    await new Promise((r) => setTimeout(r, watchMs));
  }
}

async function cmdFleetHeartbeat(args: Args): Promise<number> {
  const hb = vHeartbeat(readJsonFile(pos(args, 0, "FILE")));
  const { client } = makeClient(args);
  const r = await client.heartbeat(hb);
  out(r as unknown as Json);
  return 0;
}

async function cmdAuditExport(args: Args): Promise<number> {
  const throughSeq = flagInt(args, "through-seq");
  const { client, loaded } = makeClient(args);
  // fixed pages: exact interval + page pin updates + predecessor bundles
  type Page = { entries: unknown[]; through_seq: number; next_after: number | null; pin_updates: unknown[] };
  const entries: Json[] = [];
  const pinUpdates: Json[] = [];
  let after = 0;
  for (;;) {
    const page = (await client.audit(after, throughSeq, 100)) as unknown as Page;
    entries.push(...(page.entries as Json[]));
    pinUpdates.push(...(page.pin_updates as Json[]));
    if (page.next_after === null) break;
    after = page.next_after;
  }
  // end checkpoint: registry-signed, must be retained at through_seq
  const end = await client.checkpoint(throughSeq);
  // predecessor bundles
  const versions = (await client.charterVersions(0, 100)) as unknown as { versions: { version: number }[] };
  const bundles: Json[] = [];
  for (const v of versions.versions) bundles.push((await client.charterVersion(v.version)) as unknown as Json);
  let start: Json = null;
  const fromCp = flag(args, "from-checkpoint");
  if (fromCp !== undefined) start = readJsonFile(fromCp);
  const inputsFile = flag(args, "inputs");
  const inputs = inputsFile !== undefined ? readJsonFile(inputsFile) : [];
  const evidence = {
    schema: "bedrock.evidence/1", root: loaded.root, bundles, start,
    entries, pin_updates: pinUpdates, end, inputs,
  };
  const outPath = need(args, "out");
  writeOut(outPath, new TextEncoder().encode(canonicalString(evidence as unknown as Json)), flagBool(args, "replace"));
  out({ through_seq: throughSeq, entries: entries.length, out: outPath } as unknown as Json);
  return 0;
}

async function cmdAuditVerify(args: Args): Promise<number> {
  const file = pos(args, 0, "FILE");
  const evidence = vEvidence(readJsonFile(file));
  const root = vRootFile(readJsonFile(need(args, "root")));
  const trustedCp = flag(args, "trusted-checkpoint");
  const trusted = trustedCp !== undefined ? (readJsonFile(trustedCp) as never) : null;
  const replay = flagBool(args, "replay");
  const v = verifyEvidence(evidence, root, trusted, replay);
  out(v as unknown as Json);
  if (v.integrity === "INVALID" || v.replay === "MISMATCH") return 4;
  if (v.integrity === "INCOMPLETE" || v.replay === "INPUTS_MISSING" || v.replay === "CONTEXT_MISSING") return 8;
  return 0;
}

async function cmdServe(args: Args): Promise<number> {
  const local = flagBool(args, "local");
  const loaded = loadConfig(flag(args, "config") ?? "./bedrock.yaml");
  if (!local) {
    // validates packaged Worker configuration, prints deployment_required
    out({ deployment_required: true } as unknown as Json);
    return 0;
  }
  if (loaded.config.environment !== "local") {
    throw new BedrockError("SCHEMA", "serve --local requires environment: local");
  }
  const authRecords = loadAuthRecords(loaded.config);
  const responseKeys = loadResponseKeys(loaded.config);
  const auditSeed = loadAuditSeed(loaded.config, loaded.root);
  const manifest = vManifest(readJsonFile(resolve(loaded.dir, loaded.config.manifest_file)));
  const store = new Store(":memory:");
  const dobj = new BedrockTenantDO({
    store, config: loaded.config, root: loaded.root, manifest,
    secrets: { authRecords, auditSeed, responseKeys },
    adapter: new MemoryRecordsAdapter(),
  });
  const emu = new LocalEmulator(dobj, loaded.config.instance_id);
  const url = await emu.start({ port: Number(new URL(loaded.config.endpoint).port) || 0 });
  err(`bedrock local emulator listening on ${url}`);
  await new Promise<void>((resolve) => {
    process.on("SIGINT", () => resolve());
    process.on("SIGTERM", () => resolve());
  });
  await emu.stop();
  return 130;
}

async function cmdConfigValidate(args: Args): Promise<number> {
  const loaded = loadConfig(flag(args, "config") ?? (args.positional[0] !== undefined ? args.positional[0] : "./bedrock.yaml"));
  const manifest = vManifest(readJsonFile(resolve(loaded.dir, loaded.config.manifest_file)));
  // verify secret handles configured without revealing values
  for (const ref of [
    loaded.config.client_credential_ref, loaded.config.auth_records_ref,
    loaded.config.audit_seed_ref, loaded.config.response_keys_ref,
  ]) {
    resolveEnvRef(ref);
  }
  out({
    valid: true, manifest_hash: D("manifest", manifest),
    instance_count: loaded.config.instance_inventory.length,
  } as unknown as Json);
  return 0;
}

// ---------------------------------------------------------------------------

type Cmd = (args: Args) => Promise<number>;
const COMMANDS: Record<string, Cmd> = {
  "charter lint": cmdCharterLint,
  "charter canonicalize": cmdCharterCanonicalize,
  "charter diff": cmdCharterDiff,
  "charter sign": cmdCharterSign,
  "charter bundle": cmdCharterBundle,
  "charter verify": cmdCharterVerify,
  "charter publish": cmdCharterPublish,
  "charter fetch": cmdCharterFetch,
  "pin sign": cmdPinSign,
  "pin activate": cmdPinActivate,
  "gateway pause": cmdGatewayPause,
  "gateway status": cmdGatewayStatus,
  "gateway check": cmdGatewayCheck,
  "gateway call": cmdGatewayCall,
  "gateway result": cmdGatewayResult,
  "dispute record": cmdDisputeRecord,
  "dispute list": cmdDisputeList,
  "fleet status": cmdFleetStatus,
  "fleet heartbeat": cmdFleetHeartbeat,
  "audit export": cmdAuditExport,
  "audit verify": cmdAuditVerify,
  "serve": cmdServe,
  "config validate": cmdConfigValidate,
};

const HELP = `bedrock ${VERSION} — versioned signed charters, exact pins, enforced gateway.

Usage: bedrock <command> [flags]

Commands:
  charter lint FILE --manifest M --root R [--predecessor B]
  charter canonicalize FILE --out F [--replace]
  charter diff OLD NEW --manifest M
  charter sign FILE --manifest M --key-id ID --key-ref env:VAR --out F [--replace]
  charter bundle FILE --manifest M --signature S... --root R --out F [--predecessor B...] [--replace]
  charter verify BUNDLE --root R [--predecessor B...]
  charter publish BUNDLE --request-id ID
  charter fetch VERSION --out F [--replace]
  pin sign --bundle B --expected-revision N --request-id ID --expires-at T --key-id ID --key-ref env:VAR --out F
  pin activate UPDATE
  gateway pause --expected-revision N --request-id ID --reason TEXT
  gateway status
  gateway check REQUEST.json
  gateway call REQUEST.json
  gateway result REQUEST_ID
  dispute record FILE.json
  dispute list [--after-seq N] [--limit N]
  fleet status [--watch-ms N]
  fleet heartbeat FILE.json
  audit export --through-seq N --out F [--from-checkpoint F --inputs F --replace]
  audit verify FILE --root R [--trusted-checkpoint F --replay]
  serve --local
  config validate

Global flags: --config PATH  --json  --timeout-ms N  --version  --help
`;

export async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);
  if (flagBool(args, "version")) {
    out({ version: VERSION } as unknown as Json);
    return 0;
  }
  if (flagBool(args, "help") || args.positional.length === 0) {
    process.stdout.write(HELP);
    return args.positional.length === 0 && !flagBool(args, "help") ? 2 : 0;
  }
  const key = `${args.positional[0]} ${args.positional[1] ?? ""}`.trim();
  const cmd = COMMANDS[key] ?? COMMANDS[args.positional[0]!];
  if (!cmd) {
    err(`unknown command: ${key}`);
    return 2;
  }
  const sub: Args = { positional: args.positional.slice(key.includes(" ") ? 2 : 1), flags: args.flags, repeated: args.repeated };
  try {
    return await cmd(sub);
  } catch (e) {
    if (e instanceof ApiError) {
      out({ error: { code: e.code, retryable: e.retryable, audit_seq: e.auditSeq } } as unknown as Json);
      return exitCodeFor(e.code);
    }
    if (e instanceof BedrockError) {
      out({ error: { code: e.code, retryable: e.retryable, audit_seq: e.auditSeq } } as unknown as Json);
      return exitCodeFor(e.code);
    }
    if (e instanceof Error && (e.name === "AbortError" || e.name === "TimeoutError")) {
      out({ error: { code: "BUSY", retryable: true, audit_seq: null } } as unknown as Json);
      return 7;
    }
    throw e;
  }
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      err(String(e));
      process.exit(2);
    },
  );
}
