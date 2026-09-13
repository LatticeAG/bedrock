/**
 * Configuration loading (spec §9.1–9.2): strict YAML subset, env: secret
 * handles, path resolution relative to the config directory, and the
 * production rejection set (fixture keys, loopback endpoints, bad refs).
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { BedrockError } from "./errors.js";
import { parseYaml } from "./yaml.js";
import { parseJsonBytes } from "./canon.js";
import { sha256Hex } from "./crypto.js";
import type { AuthRecord, Config, ResponseKeys, RootFile } from "./types.js";
import { vAuthRecord, vConfig, vRootFile } from "./schema.js";
import { PUB, FIXTURE_ADAPTER_BUILD_HASH } from "./fixtures.js";

const ENV_REF = /^env:[A-Z][A-Z0-9_]{0,63}$/;

export function isEnvRef(s: string): boolean {
  return ENV_REF.test(s);
}

export function resolveEnvRef(ref: string): string {
  if (!ENV_REF.test(ref)) throw new BedrockError("SCHEMA", `bad secret reference ${ref}`);
  const v = process.env[ref.slice(4)];
  if (v === undefined) throw new BedrockError("SCHEMA", `environment variable ${ref.slice(4)} not set`);
  return v;
}

export interface LoadedConfig {
  config: Config;
  dir: string;
  root: RootFile;
}

export function loadConfig(path: string): LoadedConfig {
  let raw: string;
  try {
    raw = readFileSync(path, "utf8");
  } catch {
    throw new BedrockError("SCHEMA", `config file not found: ${path}`);
  }
  const cfg = vConfig(parseYaml(raw));
  const dir = dirname(resolve(path));
  const root = loadRoot(resolve(dir, cfg.root_file));
  // Root file tenant/gateway must equal configured values; charter/log adopted.
  if (root.tenant_id !== cfg.tenant_id || root.gateway_id !== cfg.gateway_id) {
    throw new BedrockError("SCHEMA", "root file tenant/gateway mismatch");
  }
  if (cfg.storage_soft_limit_bytes > 8589934592) {
    throw new BedrockError("SCHEMA", "storage_soft_limit_bytes exceeds the 8 GiB v1 bound");
  }
  if (cfg.max_in_flight < 1 || cfg.max_in_flight > 32) {
    throw new BedrockError("SCHEMA", "max_in_flight outside [1,32]");
  }
  const inv = new Set(cfg.instance_inventory);
  if (inv.size !== cfg.instance_inventory.length || inv.size < 1 || inv.size > 32) {
    throw new BedrockError("SCHEMA", "instance_inventory must be 1–32 distinct ids");
  }
  if (!inv.has(cfg.instance_id)) {
    throw new BedrockError("SCHEMA", "instance_id not in instance_inventory");
  }
  if (cfg.environment === "production") productionRejections(cfg, root);
  return { config: cfg, dir, root };
}

function productionRejections(cfg: Config, root: RootFile): void {
  const allKeys = [...root.bootstrap.keys, ...root.audit_keys];
  for (const k of allKeys) {
    if ((PUB as string[]).includes(k.public_key)) {
      throw new BedrockError("SCHEMA", "production rejects published fixture keys");
    }
  }
  if (!cfg.endpoint.startsWith("https://")) {
    throw new BedrockError("SCHEMA", "production endpoint must be HTTPS, non-loopback");
  }
  let u: URL;
  try {
    u = new URL(cfg.endpoint);
  } catch {
    throw new BedrockError("SCHEMA", "bad endpoint URL");
  }
  if (u.username || u.password || u.pathname !== "/" || u.search || u.hash) {
    throw new BedrockError("SCHEMA", "endpoint must be an origin without credentials/path/query/fragment");
  }
  if (["localhost", "127.0.0.1", "::1"].includes(u.hostname)) {
    throw new BedrockError("SCHEMA", "production endpoint must not be loopback");
  }
  for (const ref of [cfg.client_credential_ref, cfg.auth_records_ref, cfg.audit_seed_ref, cfg.response_keys_ref]) {
    if (!isEnvRef(ref)) throw new BedrockError("SCHEMA", "production requires env: secret handles");
  }
}

export function loadRoot(path: string): RootFile {
  const root = vRootFile(parseJsonBytes(new Uint8Array(readFileSync(path))));
  // bootstrap keys and audit keys must be disjoint; ranges per key id must not overlap
  const boot = new Set(root.bootstrap.keys.map((k) => k.public_key));
  const perId = new Map<string, { from: number; through: number | null }[]>();
  for (const k of root.audit_keys) {
    if (boot.has(k.public_key)) {
      throw new BedrockError("SCHEMA", "audit key may not be a bootstrap key");
    }
    const list = perId.get(k.key_id) ?? [];
    for (const r of list) {
      const a1 = k.from_seq, b1 = k.through_seq ?? Number.MAX_SAFE_INTEGER;
      const a2 = r.from, b2 = r.through ?? Number.MAX_SAFE_INTEGER;
      if (a1 <= b2 && a2 <= b1) {
        throw new BedrockError("SCHEMA", `audit key ${k.key_id} ranges overlap`);
      }
    }
    list.push({ from: k.from_seq, through: k.through_seq });
    perId.set(k.key_id, list);
  }
  return root;
}

export function loadAuthRecords(cfg: Config): AuthRecord[] {
  const raw = resolveEnvRef(cfg.auth_records_ref);
  const arr = parseJsonBytes(new Uint8Array(new TextEncoder().encode(raw)));
  if (!Array.isArray(arr)) throw new BedrockError("SCHEMA", "auth records must be an array");
  const records = arr.map(vAuthRecord);
  const seen = new Set<string>();
  for (const r of records) {
    if (seen.has(r.token_hash)) throw new BedrockError("SCHEMA", "duplicate credential hash");
    seen.add(r.token_hash);
    if (r.tenant_id !== cfg.tenant_id) throw new BedrockError("SCHEMA", "auth record tenant mismatch");
    const bound = r.role === "agent" || r.role === "instance";
    if (bound && (r.instance_id === null || !cfg.instance_inventory.includes(r.instance_id))) {
      throw new BedrockError("SCHEMA", "agent/instance record requires a configured instance_id");
    }
    if (!bound && r.instance_id !== null) {
      throw new BedrockError("SCHEMA", "non-agent/instance record requires instance_id null");
    }
    if (r.principal_id === cfg.system_principal_id) {
      throw new BedrockError("SCHEMA", "system_principal_id must not appear in auth records");
    }
    const sorted = [...r.scopes].sort();
    if (r.scopes.some((s, i) => s !== sorted[i]) || new Set(r.scopes).size !== r.scopes.length) {
      throw new BedrockError("SCHEMA", "principal scopes must be sorted unique");
    }
    if (r.role === "instance" && r.scopes.length > 0) {
      throw new BedrockError("SCHEMA", "instance records have no agent tool scope");
    }
  }
  return records;
}

export function loadResponseKeys(cfg: Config): ResponseKeys {
  const raw = resolveEnvRef(cfg.response_keys_ref);
  const rk = parseJsonBytes(new Uint8Array(new TextEncoder().encode(raw))) as unknown as ResponseKeys;
  if (typeof rk !== "object" || rk === null || Array.isArray(rk)) {
    throw new BedrockError("SCHEMA", "bad response keys object");
  }
  const o = rk as { active_key_id?: unknown; keys?: unknown };
  if (typeof o.active_key_id !== "string" || !Array.isArray(o.keys)) {
    throw new BedrockError("SCHEMA", "bad response keys object");
  }
  const ids = new Set<string>();
  for (const k of o.keys) {
    const kk = k as { key_id?: unknown; key_base64url?: unknown };
    if (typeof kk.key_id !== "string" || typeof kk.key_base64url !== "string") {
      throw new BedrockError("SCHEMA", "bad response key entry");
    }
    if (ids.has(kk.key_id)) throw new BedrockError("SCHEMA", "duplicate response key id");
    ids.add(kk.key_id);
    try {
      const b = Buffer.from(kk.key_base64url, "base64url");
      if (b.length !== 32 || Buffer.from(b).toString("base64url") !== kk.key_base64url) {
        throw new BedrockError("SCHEMA", "response key must be canonical base64url of 32 bytes");
      }
    } catch {
      throw new BedrockError("SCHEMA", "response key must be canonical base64url of 32 bytes");
    }
  }
  if (o.keys.length < 1 || o.keys.length > 8 || !ids.has(o.active_key_id)) {
    throw new BedrockError("SCHEMA", "response keys must be 1–8 with active id present");
  }
  return rk;
}

export function loadAuditSeed(cfg: Config, root: RootFile): Uint8Array {
  const hex = resolveEnvRef(cfg.audit_seed_ref).trim();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new BedrockError("SCHEMA", "audit seed must be 64 lowercase hex");
  const declared = root.audit_keys.find((k) => k.key_id === cfg.audit_key_id);
  if (!declared) throw new BedrockError("SCHEMA", "audit_key_id absent from root audit_keys");
  return Buffer.from(hex, "hex");
}

export function clientCredential(cfg: Config): string {
  return resolveEnvRef(cfg.client_credential_ref);
}
