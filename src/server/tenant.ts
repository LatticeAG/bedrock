/**
 * BedrockTenantDO — the per-tenant authority (spec §2, §6, §7, §10).
 * Owns publication order, the active pin, pause state, instance observations,
 * idempotency records, dispatch markers, and the audit sequence behind one
 * serialization gate. No cached positive authorization is ever accepted.
 */
import { BedrockError, apiError, httpStatusFor } from "../errors.js";
import {
  J, canonicalString, parseJsonBytes, assertCanonicalJson, type Json,
} from "../canon.js";
import { timingSafeEqual } from "node:crypto";
import {
  D, S, sha256Hex, b64urlDecode, b64urlEncode, ed25519Sign, ed25519PublicKey,
  aesGcmEncrypt, aesGcmDecrypt, type EncEnvelope,
} from "../crypto.js";
import { formatTime, parseTime } from "../time.js";
import type {
  AdapterRequest, AdapterResponse, AuditBody, AuditEntry, Bundle, CallRequest,
  CallResult, CallState, Charter, CheckpointBody, Config, Decision, Deployment,
  Dispute, Event, Fleet, InstanceState, InstanceView, MetricSnapshot,
  MutationResult, Pin, Principal, RootFile, SignedPinUpdate, Warning, AuthRecord,
  ResponseKeys, CheckResult, Manifest,
} from "../types.js";
import {
  vBundle, vCallRequest, vDisputeRequest, vHeartbeat, vPauseRequest,
  vSignedPinUpdate, vCharter, vManifest,
} from "../schema.js";
import { evaluate } from "../evaluator.js";
import { manifestDigestOrThrow, checkBundleSemantics, checkLineage, pinOf } from "../compiler.js";
import { verifyBundle, verifyPinUpdateSignatures, checkSignatures, canonicalEqual } from "../bundle.js";
import type { Store } from "./storage.js";
import type { RecordsAdapter } from "./adapter.js";

const HEARTBEAT_FRESH_MS = 180_000;
const RETENTION_MS = 24 * 60 * 60 * 1000;
const PIN_EXPIRY_MAX_AHEAD_MS = 300_000;
const CLOCK_CLAMP_MS = 1_000;
const MAX_BODY_PUBLISH = 257 * 1024;
const MAX_BODY_DEFAULT = 64 * 1024;
const OUTPUT_MAX_BYTES = 64 * 1024;
const STORAGE_RESERVE = 16 * 1024 * 1024;
const ZERO_HASH = "0".repeat(64);

export interface DoSecrets {
  authRecords: AuthRecord[];
  auditSeed: Uint8Array; // 32-byte ed25519 seed for the configured audit key
  responseKeys: ResponseKeys;
}

export interface DoDeps {
  store: Store;
  config: Config;
  root: RootFile;
  manifest: Manifest;
  secrets: DoSecrets;
  adapter: RecordsAdapter;
  nowMs?: () => number;
  /** Test-only fault injection points. */
  faults?: Set<string>;
  /** Test hook: invoked right after the adapter invocation is initiated. */
  onDispatched?: (requestId: string) => void;
}

export interface Inbound {
  method: string;
  path: string;
  headers: Record<string, string | undefined>;
  body: Uint8Array | null;
}

export interface DoResponse {
  status: number;
  body: Json;
}

/** Simulated process death; escapes fetch() the way a real crash would. */
export class CrashFault extends Error {
  constructor() {
    super("injected crash");
    this.name = "CrashFault";
  }
}

/** Serialize all tenant mutations through one promise chain (the DO gate). */
class Gate {
  private tail: Promise<unknown> = Promise.resolve();
  run<T>(fn: () => T | Promise<T>): Promise<T> {
    const p = this.tail.then(fn);
    this.tail = p.catch(() => {});
    return p;
  }
}

function nowTime(ms: number): string {
  return formatTime(ms);
}

export class BedrockTenantDO {
  private gate = new Gate();
  private clockUnsafe = false;
  private metricsWindow = -1;
  private metrics = { calls: 0, allows: 0, denies: 0, indeterminate: 0, audit_failures: 0 };
  private responseKeyMap: Map<string, Uint8Array>;

  constructor(private deps: DoDeps) {
    this.responseKeyMap = new Map(
      deps.secrets.responseKeys.keys.map((k) => [k.key_id, b64urlDecode(k.key_base64url)]),
    );
    const meta = deps.store.getMeta();
    if (!meta) {
      deps.store.tx(() => {
        const deployment: Deployment = {
          gateway_id: deps.config.gateway_id,
          revision: 0,
          state: "UNPINNED",
          pin: null,
          installed_manifest_hash: D("manifest", deps.manifest),
          in_flight: 0,
        };
        deps.store.initMeta(deployment);
        for (const iid of deps.config.instance_inventory) {
          const view: InstanceView = {
            instance_id: iid, counter: 0, received_at: null, expires_at: null,
            observed_pin: null, manifest_hash: null, state: "MISSING",
          };
          deps.store.initInstance(iid, J(view as unknown as Json));
        }
      });
    }
    this.recover();
  }

  /** Crash recovery: orphan DISPATCHED calls become INDETERMINATE; never resend. */
  private recover(): void {
    const orphans = this.deps.store.pendingCalls();
    if (orphans.length === 0) return;
    this.deps.store.tx(() => {
      for (const c of orphans) {
        const call = this.deps.store.getCall(c.principal_id, c.request_id)!;
        const seqs = JSON.parse(Buffer.from(call.audit_seqs_jcs).toString("utf8")) as number[];
        const seq = this.appendAudit(
          this.systemActor(), c.request_id, this.activePin(),
          { type: "CallFinished", value: { request_id: c.request_id, state: "INDETERMINATE", output_hash: null } },
        );
        seqs.push(seq);
        this.deps.store.finishCall(c.principal_id, c.request_id, "INDETERMINATE", null, null, J(seqs as unknown as Json));
      }
      const m = this.meta();
      m.deployment.in_flight = Math.max(0, m.deployment.in_flight - orphans.length);
      this.deps.store.putMeta(m);
    });
  }

  private systemActor(): string {
    return this.deps.config.system_principal_id;
  }
  private now(): number {
    return this.deps.nowMs ? this.deps.nowMs() : Date.now();
  }
  private meta() {
    const m = this.deps.store.getMeta();
    if (!m) throw new BedrockError("STATE_TRANSITION", "tenant store uninitialized");
    return m;
  }
  private activePin(): Pin | null {
    return this.meta().deployment.pin;
  }

  /** Clock discipline (§10.3): clamp <=1s backward, else set CLOCK_UNSAFE. */
  private authorityNow(): number {
    const now = this.now();
    const m = this.meta();
    if (now < m.last_time_ms) {
      if (m.last_time_ms - now <= CLOCK_CLAMP_MS) return m.last_time_ms;
      this.clockUnsafe = true;
      return m.last_time_ms;
    }
    return now;
  }

  private auditKeyFor(seq: number): { key_id: string; public_key: string } {
    const k = this.deps.root.audit_keys.find(
      (a) =>
        a.key_id === this.deps.config.audit_key_id &&
        a.from_seq <= seq &&
        (a.through_seq === null || seq <= a.through_seq),
    );
    if (!k) throw new BedrockError("AUDIT_UNAVAILABLE", "no audit key eligible for next sequence");
    const derived = Buffer.from(ed25519PublicKey(this.deps.secrets.auditSeed)).toString("hex");
    if (derived !== k.public_key) {
      throw new BedrockError("AUDIT_UNAVAILABLE", "audit seed does not derive to declared public key");
    }
    return k;
  }

  /** Append a signed audit entry inside the current transaction. */
  private appendAudit(actorId: string, subjectId: string, policyPin: Pin | null, event: Event): number {
    if (this.deps.faults?.has("audit_commit_before_dispatch")) {
      throw new BedrockError("AUDIT_UNAVAILABLE", "injected audit commit failure");
    }
    const m = this.meta();
    const seq = m.next_seq;
    const key = this.auditKeyFor(seq);
    const now = this.authorityNow();
    const body: AuditBody = {
      schema: "bedrock.audit/1",
      tenant_id: this.deps.config.tenant_id,
      log_id: this.deps.root.log_id,
      seq,
      prev_hash: m.head_hash,
      time: nowTime(now),
      actor_id: actorId,
      subject_id: subjectId as AuditBody["subject_id"],
      policy_pin: policyPin,
      event,
    };
    const hash = D("audit", body as unknown as Json);
    const signature = b64urlEncode(ed25519Sign(this.deps.secrets.auditSeed, S("audit", body as unknown as Json)));
    this.deps.store.appendAudit(seq, hash, J(body as unknown as Json), key.key_id, signature);
    this.deps.store.putMeta({ deployment: m.deployment, next_seq: seq + 1, head_hash: hash, last_time_ms: now });
    return seq;
  }

  private touchMetrics(): void {
    const w = Math.floor(this.now() / 60000);
    if (w !== this.metricsWindow) {
      this.metricsWindow = w;
      this.metrics = { calls: 0, allows: 0, denies: 0, indeterminate: 0, audit_failures: 0 };
    }
  }

  // =========================================================================
  // fetch(): the DO's only API — §7 methods, paths, bodies, response schemas.
  // =========================================================================

  async fetch(inb: Inbound): Promise<DoResponse> {
    try {
      return await this.dispatch(inb);
    } catch (e) {
      if (e instanceof CrashFault) throw e;
      if (e instanceof BedrockError) {
        return { status: e.statusOverride ?? httpStatusFor(e.code), body: apiError(e.code, e.auditSeq) };
      }
      throw e;
    }
  }

  private async dispatch(inb: Inbound): Promise<DoResponse> {
    const { method, path } = inb;
    if (path === "/healthz" && method === "GET") {
      return { status: 200, body: { status: "up", api: "bedrock.http/1" } };
    }
    const route = matchRoute(method, path);
    if (!route) {
      if (KNOWN_PATHS.some((p) => p.test(path.split("?")[0]!))) {
        throw new BedrockError("SCHEMA", "method unsupported on this route", 405);
      }
      throw new BedrockError("NOT_FOUND", "unknown route");
    }
    if (inb.headers["idempotency-key"] !== undefined) {
      throw new BedrockError("SCHEMA", "Idempotency-Key header is never interpreted");
    }

    const bodyLimit =
      route.name === "charter.publish" || route.name === "charter.validate"
        ? MAX_BODY_PUBLISH
        : MAX_BODY_DEFAULT;

    let bodyJson: Json = null;
    if (route.hasBody) {
      const ct = inb.headers["content-type"];
      if (ct !== "application/json" && ct !== "application/json; charset=utf-8") {
        throw new BedrockError("SCHEMA", "body routes require Content-Type: application/json");
      }
      if (!inb.body || inb.body.length === 0) throw new BedrockError("PARSE", "empty body");
      if (inb.body.length > bodyLimit) throw new BedrockError("LIMIT", "body bound exceeded");
      bodyJson = parseJsonBytes(inb.body);
    } else if (inb.body && inb.body.length > 0) {
      throw new BedrockError("SCHEMA", "read routes take no request body");
    }

    const auth = this.authenticate(inb.headers["authorization"]);
    this.checkForwardedInstance(inb.headers["x-bedrock-instance"], auth);
    if (!route.roles.includes(auth.record.role)) {
      throw new BedrockError("FORBIDDEN", `role ${auth.record.role} cannot use ${route.name}`);
    }

    switch (route.name) {
      case "readyz": return this.rReadyz();
      case "charter.validate": return this.rValidate(bodyJson);
      case "charter.publish": return this.rPublish(auth, inb, bodyJson);
      case "charter.versions": return this.rVersions(inb);
      case "charter.version": return this.rVersion(route.params["v"]!);
      case "deployment.get": return { status: 200, body: this.meta().deployment as unknown as Json };
      case "deployment.pin": return this.rPin(auth, inb, bodyJson);
      case "deployment.pause": return this.rPause(auth, inb, bodyJson);
      case "gateway.check": return this.rCheck(auth, inb, bodyJson);
      case "gateway.call": return this.rCall(auth, inb, bodyJson);
      case "gateway.call.get": return this.rCallGet(auth, route.params["id"]!);
      case "disputes.create": return this.rDispute(auth, inb, bodyJson);
      case "disputes.list": return this.rDisputeList(auth, inb);
      case "fleet.heartbeat": return this.rHeartbeat(auth, inb, bodyJson);
      case "fleet.get": return this.rFleet();
      case "audit.list": return this.rAudit(inb);
      case "audit.checkpoint": return this.gate.run(() => this.rCheckpoint(inb));
      case "metrics": return this.rMetrics();
      default: throw new BedrockError("NOT_FOUND", "unknown route");
    }
  }

  // --- auth --------------------------------------------------------------------

  private authenticate(header: string | undefined): { record: AuthRecord; principal: Principal } {
    if (!header || !header.startsWith("Bearer ")) {
      throw new BedrockError("AUTH_REQUIRED", "missing bearer credential");
    }
    const token = header.slice(7);
    const hash = sha256Hex(new TextEncoder().encode(token));
    const now = this.now();
    for (const rec of this.deps.secrets.authRecords) {
      if (rec.tenant_id !== this.deps.config.tenant_id) continue;
      const a = Buffer.from(rec.token_hash, "hex");
      const b = Buffer.from(hash, "hex");
      if (a.length !== b.length || !timingSafeEqual(a, b)) continue;
      if (now >= parseTime(rec.expires_at)) continue;
      return { record: rec, principal: { principal_id: rec.principal_id, scopes: rec.scopes } };
    }
    throw new BedrockError("AUTH_REQUIRED", "invalid or expired credential");
  }

  private checkForwardedInstance(fwd: string | undefined, auth: { record: AuthRecord }): void {
    if (!fwd || !this.deps.config.instance_inventory.includes(fwd)) {
      throw new BedrockError("NOT_FOUND", "forwarded instance not in inventory");
    }
    if (
      (auth.record.role === "agent" || auth.record.role === "instance") &&
      auth.record.instance_id !== fwd
    ) {
      throw new BedrockError("NOT_FOUND", "forwarded instance inconsistent with credential");
    }
  }

  // --- shared helpers ------------------------------------------------------------

  private requestHash(method: string, path: string, body: Json): string {
    return sha256Hex(J({ method, path, body } as unknown as Json));
  }

  /**
   * Idempotency lookup across the requests and calls stores together —
   * the (tenant, principal, request_id) namespace is shared across routes.
   */
  private idempotentLookup(
    principal: string, requestId: string, method: string, path: string, body: Json,
  ): { kind: "miss" } | { kind: "replay"; status: number; body: Json } {
    const bodyHash = this.requestHash(method, path, body);
    const req = this.deps.store.getRequest(principal, requestId);
    const call = this.deps.store.getCall(principal, requestId);
    if (!req && !call) return { kind: "miss" };
    if (req && req.body_hash !== bodyHash) {
      throw new BedrockError("IDEMPOTENCY_CONFLICT", "request id reused with different body");
    }
    if (req) {
      if (req.response_until_ms < this.now() || !req.result_jcs) {
        const tomb = req.result_jcs
          ? (JSON.parse(Buffer.from(req.result_jcs).toString("utf8")) as { body?: Json })
          : {};
        const seq = tomb.body && typeof tomb.body === "object" && !Array.isArray(tomb.body)
          ? ((tomb.body as Record<string, Json>)["audit_seq"] ?? null)
          : null;
        const e = new BedrockError("REQUEST_ID_REUSED", "request id retained past response window");
        e.auditSeq = typeof seq === "number" ? seq : null;
        throw e;
      }
      if (call) {
        // Call state is authoritative and may have advanced past the stored
        // response (completion or crash recovery); return the live CallResult.
        const res = this.callResult(principal, requestId);
        return { kind: "replay", status: res.status, body: res.body };
      }
      const stored = JSON.parse(Buffer.from(req.result_jcs).toString("utf8")) as { status: number; body: Json };
      return { kind: "replay", status: stored.status, body: stored.body };
    }
    // call row exists without a requests row — rebuild the CallResult.
    const res = this.callResult(principal, requestId);
    return { kind: "replay", status: res.status, body: res.body };
  }

  private storeIdempotent(
    principal: string, requestId: string, operation: string,
    method: string, path: string, body: Json, status: number, result: Json,
  ): void {
    const bodyHash = this.requestHash(method, path, body);
    const resultJcs = J({ status, body: result } as unknown as Json);
    const aad = J({
      tenant_id: this.deps.config.tenant_id, principal_id: principal,
      request_id: requestId, column: "response_enc",
    } as unknown as Json);
    const env = aesGcmEncrypt(
      this.responseKeyMap.get(this.deps.secrets.responseKeys.active_key_id)!,
      this.deps.secrets.responseKeys.active_key_id, aad, resultJcs,
    );
    this.deps.store.insertRequest(
      principal, requestId, operation, bodyHash,
      new TextEncoder().encode(canonicalString(env as unknown as Json)),
      this.now() + RETENTION_MS, resultJcs,
    );
  }

  private updateIdempotentResponse(principal: string, requestId: string, status: number, result: Json): void {
    const resultJcs = J({ status, body: result } as unknown as Json);
    const aad = J({
      tenant_id: this.deps.config.tenant_id, principal_id: principal,
      request_id: requestId, column: "response_enc",
    } as unknown as Json);
    const env = aesGcmEncrypt(
      this.responseKeyMap.get(this.deps.secrets.responseKeys.active_key_id)!,
      this.deps.secrets.responseKeys.active_key_id, aad, resultJcs,
    );
    this.deps.store.updateRequestResponse(
      principal, requestId,
      new TextEncoder().encode(canonicalString(env as unknown as Json)), resultJcs,
    );
  }

  private checkStoragePressure(): void {
    const used = this.deps.store.approximateBytes();
    const cap = this.deps.config.storage_soft_limit_bytes;
    if (cap - used < STORAGE_RESERVE || used >= cap) {
      throw new BedrockError("STORAGE_FULL", "storage cap/reserve reached");
    }
  }

  /**
   * Mutating-command wrapper: inside the gate, one transaction performs the
   * idempotent lookup (answered before readiness reevaluation) then the work.
   * Well-formed post-authorization failures append CommandRejected.
   */
  private async mutating(
    auth: { record: AuthRecord; principal: Principal },
    inb: Inbound, body: Json, requestId: string, operation: string,
    allowUnderClockUnsafe: boolean,
    fn: () => { status: number; body: Json },
  ): Promise<DoResponse> {
    if (this.clockUnsafe && !allowUnderClockUnsafe) {
      throw new BedrockError("CLOCK_UNSAFE", "clock regression; only pause is admissible");
    }
    try {
      return await this.gate.run(() =>
        this.deps.store.tx(() => {
          const hit = this.idempotentLookup(auth.record.principal_id, requestId, inb.method, inb.path, body);
          if (hit.kind === "replay") return { status: hit.status, body: hit.body };
          this.checkStoragePressure();
          return fn();
        }),
      );
    } catch (e) {
      throw this.auditRejection(e, auth, operation, inb, body, requestId);
    }
  }

  private auditRejection(
    e: unknown, auth: { record: AuthRecord }, operation: string, inb: Inbound, body: Json,
    requestId: string,
  ): never {
    if (e instanceof CrashFault) throw e;
    if (!(e instanceof BedrockError)) throw e;
    if (e.code === "AUDIT_UNAVAILABLE") {
      this.touchMetrics();
      this.metrics.audit_failures++;
      e.auditSeq = null;
      throw e;
    }
    if (!isAuditedRejection(e.code)) throw e;
    try {
      const seq = this.gateAppendCommandRejected(
        auth, operation, this.requestHash(inb.method, inb.path, body), e.code, requestId,
      );
      e.auditSeq = seq;
    } catch {
      e.auditSeq = null;
    }
    throw e;
  }

  private gateAppendCommandRejected(
    auth: { record: AuthRecord }, operation: string, requestHash: string, code: string,
    requestId: string,
  ): number {
    return this.deps.store.tx(() =>
      this.appendAudit(auth.record.principal_id, requestId, this.activePin(), {
        type: "CommandRejected",
        value: { operation, code, request_hash: requestHash },
      }),
    );
  }

  // --- health/readiness ------------------------------------------------------------

  private checkStorageReadiness(): void {
    this.meta();
    if (this.deps.faults?.has("storage_down")) {
      throw new BedrockError("AUDIT_UNAVAILABLE", "storage down");
    }
  }

  private loadBundle(version: number): Bundle | null {
    const row = this.deps.store.charterByVersion(version);
    if (!row) return null;
    return parseJsonBytes(new Uint8Array(row.bundle_jcs)) as unknown as Bundle;
  }

  private checkServingInstance(pin: Pin): void {
    const iid = this.deps.config.instance_id;
    const inst = this.deps.store.getInstance(iid);
    if (!inst) throw new BedrockError("INSTANCE_STALE", "serving instance not configured");
    const now = this.now();
    const fresh = inst.received_ms !== null && now < inst.received_ms + HEARTBEAT_FRESH_MS;
    if (!fresh) throw new BedrockError("INSTANCE_STALE", "serving instance observation stale");
    const view = JSON.parse(Buffer.from(inst.view_jcs).toString("utf8")) as InstanceView;
    if (view.state !== "MATCHED" || !view.observed_pin || !canonicalEqual(view.observed_pin, pin)) {
      throw new BedrockError("INSTANCE_MISMATCH", "serving instance observes a different pin");
    }
  }

  private rReadyz(): DoResponse {
    const m = this.meta();
    this.checkStorageReadiness();
    this.auditKeyFor(m.next_seq);
    if (this.clockUnsafe) throw new BedrockError("CLOCK_UNSAFE", "unsafe clock");
    if (m.deployment.state === "PAUSED") throw new BedrockError("PAUSED", "gateway paused");
    if (m.deployment.state === "UNPINNED" || m.deployment.pin === null) {
      throw new BedrockError("UNPINNED", "no active pin");
    }
    if (m.deployment.installed_manifest_hash !== m.deployment.pin.manifest_hash) {
      throw new BedrockError("MANIFEST_UNAVAILABLE", "signed manifest not installed");
    }
    const bundle = this.loadBundle(m.deployment.pin.version);
    if (!bundle || D("charter", bundle.charter) !== m.deployment.pin.charter_hash) {
      throw new BedrockError("MANIFEST_UNAVAILABLE", "pinned charter bytes unavailable");
    }
    const now = this.now();
    if (now < parseTime(bundle.charter.not_before) || now >= parseTime(bundle.charter.not_after)) {
      throw new BedrockError("POLICY_INACTIVE", "charter outside validity interval");
    }
    this.checkServingInstance(m.deployment.pin);
    return {
      status: 200,
      body: { ready: true, revision: m.deployment.revision, pin: m.deployment.pin } as unknown as Json,
    };
  }

  /** The pre-evaluation gate shared by check and call (§7.1 order). */
  private preEvalGate(): { charter: Charter; manifest: Manifest } {
    this.checkStorageReadiness();
    this.auditKeyFor(this.meta().next_seq);
    if (this.clockUnsafe) throw new BedrockError("CLOCK_UNSAFE", "unsafe clock");
    const m = this.meta();
    if (m.deployment.state === "PAUSED") throw new BedrockError("PAUSED", "gateway paused");
    if (m.deployment.state === "UNPINNED" || m.deployment.pin === null) {
      throw new BedrockError("UNPINNED", "no active pin");
    }
    const pin = m.deployment.pin;
    if (m.deployment.installed_manifest_hash !== pin.manifest_hash) {
      throw new BedrockError("MANIFEST_UNAVAILABLE", "signed manifest not installed");
    }
    if (m.deployment.in_flight >= this.deps.config.max_in_flight) {
      throw new BedrockError("BUSY", "in-flight bound exceeded");
    }
    this.checkServingInstance(pin);
    const bundle = this.loadBundle(pin.version);
    if (!bundle || D("charter", bundle.charter) !== pin.charter_hash) {
      throw new BedrockError("MANIFEST_UNAVAILABLE", "pinned charter bytes unavailable");
    }
    if (manifestDigestOrThrow(bundle.charter, bundle.manifest) !== pin.manifest_hash) {
      throw new BedrockError("MANIFEST_UNAVAILABLE", "installed manifest digest mismatch");
    }
    return { charter: bundle.charter, manifest: bundle.manifest };
  }

  // --- charter registry --------------------------------------------------------------

  private allBundles(): Bundle[] {
    const out: Bundle[] = [];
    const head = this.deps.store.charterHead();
    if (!head) return out;
    for (let v = 1; v <= head.version; v++) {
      const b = this.loadBundle(v);
      if (b) out.push(b);
    }
    return out;
  }

  private computeWarnings(charter: Charter): Warning[] {
    const w: Warning[] = [];
    if (charter.scope_rules.length === 0) w.push("NO_ALLOW_RULES");
    if (charter.next_authority.threshold === 1) w.push("SINGLE_SIGNER");
    if (parseTime(charter.not_after) - this.now() <= 24 * 3600 * 1000) w.push("EXPIRY_WITHIN_24H");
    return w.sort();
  }

  private rValidate(body: Json): DoResponse {
    const req = obj(body, ["bundle"]);
    const b = vBundle(req["bundle"]);
    vCharter(b.charter);
    vManifest(b.manifest);
    manifestDigestOrThrow(b.charter, b.manifest);
    const chain = this.allBundles();
    const pred = chain.find((x) => x.charter.version === b.charter.version - 1) ?? null;
    const authority = b.charter.version === 1
      ? this.deps.root.bootstrap
      : pred
        ? pred.charter.next_authority
        : (() => { throw new BedrockError("VERSION_CONFLICT", "no predecessor for candidate version"); })();
    checkSignatures(b.charter, "charter", b.signatures, authority);
    checkBundleSemantics(b.charter, b.manifest);
    checkLineage(b.charter, b.manifest, this.deps.root);
    return {
      status: 200,
      body: {
        valid: true,
        charter_hash: D("charter", b.charter),
        signatures: b.signatures.length,
        required: authority.threshold,
        warnings: this.computeWarnings(b.charter),
      } as unknown as Json,
    };
  }

  private rPublish(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const req = obj(body, ["request_id", "bundle"]);
    const requestId = vRequestId(req["request_id"]);
    const bundle = vBundle(req["bundle"]);
    return this.mutating(auth, inb, body, requestId, "charter.publish", false, () => {
      const chain = this.allBundles();
      const head = this.deps.store.charterHead();
      const pin = pinOf(bundle.charter, manifestDigestOrThrow(bundle.charter, bundle.manifest));
      // Permanent charter-hash dedup returns the original publication response.
      const existing = this.deps.store.charterByHash(pin.charter_hash);
      if (existing) {
        return {
          status: 201,
          body: { pin, head_version: existing.version, audit_seq: existing.published_seq } as unknown as Json,
        };
      }
      // Occupied-version CAS before chain verification of candidates.
      if (head && bundle.charter.version <= head.version) {
        throw new BedrockError("VERSION_CONFLICT", "version occupied");
      }
      verifyBundle(bundle, this.deps.root, chain);
      const now = this.now();
      if (!(parseTime(bundle.charter.issued_at) <= now && now < parseTime(bundle.charter.not_after))) {
        throw new BedrockError("SCHEMA", "outside publication time bounds");
      }
      const seq = this.appendAudit(
        auth.record.principal_id, bundle.charter.charter_id, pin,
        { type: "CharterPublished", value: { pin, source: bundle.charter.source } },
      );
      this.deps.store.insertCharter(
        bundle.charter.version, pin.charter_hash, bundle.charter.previous_hash,
        J(bundle as unknown as Json), seq,
      );
      const result = { pin, head_version: bundle.charter.version, audit_seq: seq } as unknown as Json;
      this.storeIdempotent(auth.record.principal_id, requestId, "charter.publish", inb.method, inb.path, body, 201, result);
      return { status: 201, body: result };
    });
  }

  private rVersions(inb: Inbound): DoResponse {
    const q = parseQuery(inb.path);
    const afterN = parseUintParam(q.get("after") ?? "0");
    const limitN = parseUintParam(q.get("limit") ?? "100");
    if (limitN < 1 || limitN > 100) throw new BedrockError("SCHEMA", "limit outside [1,100]");
    const rows = this.deps.store.charterVersions(afterN, limitN + 1);
    const pins: Pin[] = rows.slice(0, limitN).map((r) => {
      const b = this.loadBundle(r.version)!;
      return pinOf(b.charter, D("manifest", b.manifest));
    });
    const head = this.deps.store.charterHead();
    const more = rows.length > limitN;
    return {
      status: 200,
      body: {
        versions: pins as unknown as Json,
        head_version: head ? head.version : 0,
        next_after: more && pins.length > 0 ? pins[pins.length - 1]!.version : null,
      } as unknown as Json,
    };
  }

  private rVersion(vParam: string): DoResponse {
    if (!/^[1-9][0-9]*$/.test(vParam)) throw new BedrockError("SCHEMA", "bad version path parameter");
    const bundle = this.loadBundle(Number(vParam));
    if (!bundle) throw new BedrockError("NOT_FOUND", "version absent");
    return { status: 200, body: bundle as unknown as Json };
  }

  // --- deployment -------------------------------------------------------------------

  private rPin(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const u = vSignedPinUpdate(body);
    const requestId = u.update.request_id;
    return this.mutating(auth, inb, body, requestId, "deployment.pin", false, () => {
      const now = this.authorityNow();
      const head = this.deps.store.charterHead();
      if (!head) throw new BedrockError("PIN_NOT_HEAD", "no published head");
      const headBundle = this.loadBundle(head.version)!;
      verifyPinUpdateSignatures(
        u, headBundle.charter.next_authority,
        this.deps.config.tenant_id, this.deps.config.gateway_id,
      );
      if (now >= parseTime(u.update.expires_at) || parseTime(u.update.expires_at) - now > PIN_EXPIRY_MAX_AHEAD_MS) {
        throw new BedrockError("PIN_EXPIRED", "pin update expired or expiry beyond bound");
      }
      const m = this.meta();
      if (u.update.expected_revision !== m.deployment.revision) {
        throw new BedrockError("REVISION_CONFLICT", "expected_revision mismatch");
      }
      const headPin = pinOf(headBundle.charter, D("manifest", headBundle.manifest));
      if (!canonicalEqual(u.update.target, headPin)) {
        throw new BedrockError("PIN_NOT_HEAD", "target is not the published head");
      }
      if (m.deployment.installed_manifest_hash !== u.update.target.manifest_hash) {
        throw new BedrockError("MANIFEST_UNAVAILABLE", "signed manifest not installed");
      }
      if (now < parseTime(headBundle.charter.not_before) || now >= parseTime(headBundle.charter.not_after)) {
        throw new BedrockError("POLICY_INACTIVE", "charter outside validity interval");
      }
      const newRevision = m.deployment.revision + 1;
      const updateHash = D("pin", u.update as unknown as Json);
      const previousPin = m.deployment.pin;
      m.deployment.pin = u.update.target;
      m.deployment.state = "ACTIVE";
      m.deployment.revision = newRevision;
      this.deps.store.putMeta(m);
      let seq = this.appendAudit(
        auth.record.principal_id, headBundle.charter.charter_id, u.update.target,
        {
          type: "PinActivated",
          value: {
            revision: newRevision, previous_pin: previousPin, pin: u.update.target,
            update_hash: updateHash, in_flight: m.deployment.in_flight,
          },
        },
      );
      this.deps.store.insertPinUpdate(newRevision, updateHash, J(u as unknown as Json), seq);
      for (const inst of this.deps.store.allInstances()) {
        const ev = this.reclassify(inst.instance_id, u.update.target, now);
        if (ev) seq = this.appendAudit(auth.record.principal_id, inst.instance_id, u.update.target, ev);
      }
      const result: MutationResult = {
        revision: newRevision, state: "ACTIVE", pin: u.update.target,
        in_flight: m.deployment.in_flight, audit_seq: seq,
      };
      this.storeIdempotent(auth.record.principal_id, requestId, "deployment.pin", inb.method, inb.path, body, 200, result as unknown as Json);
      return { status: 200, body: result as unknown as Json };
    });
  }

  /** Recompute one instance's classification after a pin change. */
  private reclassify(instanceId: string, pin: Pin, now: number): Event | null {
    const inst = this.deps.store.getInstance(instanceId);
    if (!inst) return null;
    const view = JSON.parse(Buffer.from(inst.view_jcs).toString("utf8")) as InstanceView;
    const fresh = inst.received_ms !== null && now < inst.received_ms + HEARTBEAT_FRESH_MS;
    const from: InstanceState = fresh ? view.state : "MISSING";
    const to: InstanceState = !fresh
      ? "MISSING"
      : view.observed_pin !== null &&
          canonicalEqual(view.observed_pin, pin) &&
          view.manifest_hash === pin.manifest_hash
        ? "MATCHED"
        : "MISMATCH";
    view.state = to;
    this.deps.store.putInstance(instanceId, inst.counter, inst.received_ms, J(view as unknown as Json));
    if (from === to) return null;
    return { type: "FleetStatusChanged", value: { instance_id: instanceId, from, to, counter: inst.counter } };
  }

  private rPause(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const req = vPauseRequest(body);
    return this.mutating(auth, inb, body, req.request_id, "deployment.pause", true, () => {
      const now = this.authorityNow();
      const m = this.meta();
      if (req.expected_revision !== m.deployment.revision) {
        throw new BedrockError("REVISION_CONFLICT", "expected_revision mismatch");
      }
      m.deployment.revision += 1;
      m.deployment.state = "PAUSED";
      this.deps.store.putMeta(m);
      const seq = this.appendAudit(
        auth.record.principal_id, this.deps.root.log_id, m.deployment.pin,
        { type: "GatewayPaused", value: { revision: m.deployment.revision, reason: req.reason, in_flight: m.deployment.in_flight } },
      );
      const result: MutationResult = {
        revision: m.deployment.revision, state: "PAUSED", pin: m.deployment.pin,
        in_flight: m.deployment.in_flight, audit_seq: seq,
      };
      this.storeIdempotent(auth.record.principal_id, req.request_id, "deployment.pause", inb.method, inb.path, body, 200, result as unknown as Json);
      return { status: 200, body: result as unknown as Json };
    });
  }

  // --- gateway ------------------------------------------------------------------------

  private evalContext(
    auth: { record: AuthRecord; principal: Principal }, req: CallRequest,
  ): { charter: Charter; manifest: Manifest; decision: Decision; input_hash: string; nowMs: number } {
    const gate = this.preEvalGate();
    const nowMs = this.authorityNow();
    const input_hash = D("input", { request: req, principal: auth.principal } as unknown as Json);
    const decision = evaluate({
      charter: gate.charter, manifest: gate.manifest, active_pin: this.activePin()!,
      request: req, principal: auth.principal, now: nowTime(nowMs),
    });
    return { charter: gate.charter, manifest: gate.manifest, decision, input_hash, nowMs };
  }

  private rCheck(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const req = vCallRequest(body);
    return this.mutating(auth, inb, body, req.request_id, "gateway.check", false, () => {
      const ctx = this.evalContext(auth, req);
      const seq = this.appendAudit(auth.record.principal_id, req.request_id, this.activePin(), {
        type: "CheckEvaluated",
        value: { request_id: req.request_id, input_hash: ctx.input_hash, evaluated_at: nowTime(ctx.nowMs), decision: ctx.decision },
      });
      const result: CheckResult = {
        decision: ctx.decision, input_hash: ctx.input_hash, enforcement: false, audit_seq: seq,
      };
      this.storeIdempotent(auth.record.principal_id, req.request_id, "gateway.check", inb.method, inb.path, body, 200, result as unknown as Json);
      return { status: 200, body: result as unknown as Json };
    });
  }

  private async rCall(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const req = vCallRequest(body);
    const principal = auth.record.principal_id;
    if (this.clockUnsafe) throw new BedrockError("CLOCK_UNSAFE", "unsafe clock");

    let adapterPromise: Promise<AdapterResponse> | null = null;
    interface Dispatched {
      kind: "denied" | "dispatched" | "replay";
      ctx?: { charter: Charter; manifest: Manifest; decision: Decision; input_hash: string; nowMs: number };
      response?: DoResponse;
    }
    let phase: Dispatched;
    try {
      phase = await this.gate.run(async () => {
        // Phase A: admission + durable dispatch marker (one transaction).
        const r = this.deps.store.tx((): Dispatched => {
          const hit = this.idempotentLookup(principal, req.request_id, inb.method, inb.path, body);
          if (hit.kind === "replay") return { kind: "replay", response: { status: hit.status, body: hit.body } };
          this.checkStoragePressure();
          const ctx = this.evalContext(auth, req);
          const deadlineMs = parseTime(req.deadline);
          if (ctx.decision.verdict === "DENY") {
            const seq = this.appendAudit(principal, req.request_id, this.activePin(), {
              type: "CallDenied",
              value: { request_id: req.request_id, input_hash: ctx.input_hash, evaluated_at: nowTime(ctx.nowMs), decision: ctx.decision },
            });
            this.deps.store.insertCall(principal, req.request_id, ctx.input_hash, "DENIED", J(ctx.decision as unknown as Json), deadlineMs, J([seq] as unknown as Json));
            const result: CallResult = {
              request_id: req.request_id, state: "DENIED", decision: ctx.decision,
              input_hash: ctx.input_hash, output: null, output_available: false,
              output_hash: null, audit_seqs: [seq],
            };
            this.storeIdempotent(principal, req.request_id, "gateway.call", inb.method, inb.path, body, 200, result as unknown as Json);
            this.touchMetrics();
            this.metrics.calls++;
            this.metrics.denies++;
            return { kind: "denied", ctx, response: { status: 200, body: result as unknown as Json } };
          }
          // ALLOW → durable DISPATCHED marker + CallDispatched + idempotency row.
          const seq = this.appendAudit(principal, req.request_id, this.activePin(), {
            type: "CallDispatched",
            value: { request_id: req.request_id, input_hash: ctx.input_hash, evaluated_at: nowTime(ctx.nowMs), decision: ctx.decision },
          });
          this.deps.store.insertCall(principal, req.request_id, ctx.input_hash, "DISPATCHED", J(ctx.decision as unknown as Json), deadlineMs, J([seq] as unknown as Json));
          const pending: CallResult = {
            request_id: req.request_id, state: "DISPATCHED", decision: ctx.decision,
            input_hash: ctx.input_hash, output: null, output_available: false,
            output_hash: null, audit_seqs: [seq],
          };
          this.storeIdempotent(principal, req.request_id, "gateway.call", inb.method, inb.path, body, 202, pending as unknown as Json);
          const m2 = this.meta(); // fresh: appendAudit advanced next_seq
          m2.deployment.in_flight += 1;
          this.deps.store.putMeta(m2);
          this.touchMetrics();
          this.metrics.calls++;
          this.metrics.allows++;
          return { kind: "dispatched", ctx };
        });
        // Marker is durable. Initiate the single adapter invocation before the
        // gate is released; a crash here is INDETERMINATE on recovery — never resent.
        if (r.kind === "dispatched") {
          if (this.deps.faults?.has("crash_after_marker")) throw new CrashFault();
          const ctx = r.ctx!;
          const tool = ctx.manifest.tools.find((t) => t.tool === req.tool)!;
          const areq: AdapterRequest = {
            request_id: req.request_id, principal_id: principal, scope: req.scope,
            pin: this.activePin()!, input_hash: ctx.input_hash,
            operation: tool.operation, resource: req.resource, args: req.args,
            deadline: req.deadline,
          };
          adapterPromise = this.deps.adapter.run(areq);
          this.deps.onDispatched?.(req.request_id);
        }
        return r;
      });
    } catch (e) {
      throw this.auditRejection(e, auth, "gateway.call", inb, body, req.request_id);
    }

    if (phase.kind !== "dispatched") return phase.response!;
    const ctx = phase.ctx!;

    // Phase B: await the initiated invocation; deadline/uncertainty → INDETERMINATE.
    let outcome: { state: "SUCCEEDED" | "FAILED" | "INDETERMINATE"; output: Json; output_hash: string | null };
    try {
      const deadlineMs = parseTime(req.deadline);
      const timeoutMs = Math.max(0, deadlineMs - this.now());
      const resp = await Promise.race<AdapterResponse | null>([
        adapterPromise!,
        new Promise<null>((res) => setTimeout(() => res(null), timeoutMs)),
      ]);
      if (resp === null || resp.status === "unknown") {
        outcome = { state: "INDETERMINATE", output: null, output_hash: null };
      } else {
        try {
          assertCanonicalJson(resp.output, OUTPUT_MAX_BYTES);
          outcome = {
            state: resp.status === "ok" ? "SUCCEEDED" : "FAILED",
            output: resp.output,
            output_hash: sha256Hex(J(resp.output)),
          };
        } catch {
          outcome = { state: "INDETERMINATE", output: null, output_hash: null };
        }
      }
    } catch {
      outcome = { state: "INDETERMINATE", output: null, output_hash: null };
    }

    // Phase C: completion transaction with CallFinished.
    try {
      return await this.gate.run(() =>
        this.deps.store.tx((): DoResponse => {
          const call = this.deps.store.getCall(principal, req.request_id);
          if (!call || call.state !== "DISPATCHED") {
            return this.callResult(principal, req.request_id); // terminal record stands
          }
          const seqs = JSON.parse(Buffer.from(call.audit_seqs_jcs).toString("utf8")) as number[];
          if (this.deps.faults?.has("crash_before_finish")) throw new CrashFault();
          const seq = this.appendAudit(principal, req.request_id, this.activePin(), {
            type: "CallFinished",
            value: { request_id: req.request_id, state: outcome.state, output_hash: outcome.output_hash },
          });
          seqs.push(seq);
          const outputEnc = outcome.output !== null
            ? new TextEncoder().encode(canonicalString(
                this.encryptOutput(principal, req.request_id, outcome.output) as unknown as Json,
              ))
            : null;
          this.deps.store.finishCall(principal, req.request_id, outcome.state, outputEnc, outcome.output_hash, J(seqs as unknown as Json));
          const m = this.meta();
          m.deployment.in_flight = Math.max(0, m.deployment.in_flight - 1);
          this.deps.store.putMeta(m);
          if (outcome.state === "INDETERMINATE") {
            this.touchMetrics();
            this.metrics.indeterminate++;
          }
          const result: CallResult = {
            request_id: req.request_id, state: outcome.state, decision: ctx.decision,
            input_hash: ctx.input_hash, output: outcome.output,
            output_available: outcome.output !== null, output_hash: outcome.output_hash,
            audit_seqs: seqs,
          };
          const status = outcome.state === "INDETERMINATE" ? 202 : 200;
          this.updateIdempotentResponse(principal, req.request_id, status, result as unknown as Json);
          return { status, body: result as unknown as Json };
        }),
      );
    } catch (e) {
      if (e instanceof BedrockError && e.code === "AUDIT_UNAVAILABLE") {
        this.touchMetrics();
        this.metrics.audit_failures++;
      }
      throw e;
    }
  }

  private encryptOutput(principal: string, requestId: string, output: Json): EncEnvelope {
    const aad = J({
      tenant_id: this.deps.config.tenant_id, principal_id: principal,
      request_id: requestId, column: "output_enc",
    } as unknown as Json);
    return aesGcmEncrypt(
      this.responseKeyMap.get(this.deps.secrets.responseKeys.active_key_id)!,
      this.deps.secrets.responseKeys.active_key_id, aad, J(output),
    );
  }

  private decryptOutput(principal: string, requestId: string, blob: Uint8Array): Json | null {
    try {
      const env = JSON.parse(Buffer.from(blob).toString("utf8")) as EncEnvelope;
      const aad = J({
        tenant_id: this.deps.config.tenant_id, principal_id: principal,
        request_id: requestId, column: "output_enc",
      } as unknown as Json);
      const pt = aesGcmDecrypt(this.responseKeyMap, aad, env);
      if (!pt) return null;
      return parseJsonBytes(pt) as Json;
    } catch {
      return null;
    }
  }

  private callResult(principal: string, requestId: string): DoResponse {
    const call = this.deps.store.getCall(principal, requestId);
    if (!call) throw new BedrockError("NOT_FOUND", "call absent or invisible");
    const decision = JSON.parse(Buffer.from(call.decision_jcs).toString("utf8")) as Decision;
    const seqs = JSON.parse(Buffer.from(call.audit_seqs_jcs).toString("utf8")) as number[];
    const output = call.output_enc ? this.decryptOutput(principal, requestId, call.output_enc) : null;
    const result: CallResult = {
      request_id: requestId, state: call.state as CallState, decision,
      input_hash: call.input_hash, output, output_available: output !== null,
      output_hash: call.output_hash, audit_seqs: seqs,
    };
    const status = call.state === "DISPATCHED" || call.state === "INDETERMINATE" ? 202 : 200;
    return { status, body: result as unknown as Json };
  }

  private rCallGet(auth: { record: AuthRecord }, idParam: string): DoResponse {
    if (!/^brq_[A-Za-z0-9_-]{21}$/.test(idParam)) {
      throw new BedrockError("SCHEMA", "bad request id");
    }
    const owner = this.callOwner(idParam);
    if (!owner) throw new BedrockError("NOT_FOUND", "call absent or invisible");
    if (auth.record.role === "agent" && owner !== auth.record.principal_id) {
      throw new BedrockError("NOT_FOUND", "call absent or invisible");
    }
    return this.callResult(owner, idParam);
  }

  private callOwner(requestId: string): string | null {
    const r = this.deps.store.db
      .prepare("SELECT principal_id FROM calls WHERE request_id=? LIMIT 1")
      .get(requestId) as { principal_id: string } | undefined;
    return r ? r.principal_id : null;
  }

  // --- disputes ---------------------------------------------------------------------

  private rDispute(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const req = vDisputeRequest(body);
    return this.mutating(auth, inb, body, req.request_id, "disputes.create", false, () => {
      const entry = this.deps.store.auditEntry(req.audit_seq);
      if (!entry) throw new BedrockError("NOT_FOUND", "cited audit entry absent");
      const cited = JSON.parse(Buffer.from(entry.body_jcs).toString("utf8")) as AuditBody;
      if (auth.record.role === "agent" && cited.actor_id !== auth.record.principal_id) {
        throw new BedrockError("NOT_FOUND", "cited audit entry invisible");
      }
      if (cited.policy_pin === null || !canonicalEqual(cited.policy_pin, req.pin)) {
        throw new BedrockError("HASH_MISMATCH", "dispute pin does not equal cited entry pin");
      }
      const eh = req.evidence_hashes;
      for (let i = 1; i < eh.length; i++) {
        if (eh[i - 1]! >= eh[i]!) throw new BedrockError("SCHEMA", "evidence_hashes not sorted/unique");
      }
      // dispute_id reuse under any other request/body conflicts
      if (this.deps.store.disputeById(req.dispute_id)) {
        throw new BedrockError("IDEMPOTENCY_CONFLICT", "dispute_id already recorded");
      }
      const now = this.authorityNow();
      const seq = this.appendAudit(auth.record.principal_id, req.dispute_id, req.pin, {
        type: "DisputeRecorded",
        value: { dispute_id: req.dispute_id, cited_seq: req.audit_seq, category: req.category },
      });
      const dispute: Dispute = {
        ...req, actor_id: auth.record.principal_id, recorded_at: nowTime(now),
        status: "RECORDED_ADVISORY", receipt_seq: seq,
      };
      this.deps.store.insertDispute(req.dispute_id, auth.record.principal_id, seq, J(dispute as unknown as Json));
      this.storeIdempotent(auth.record.principal_id, req.request_id, "disputes.create", inb.method, inb.path, body, 201, dispute as unknown as Json);
      return { status: 201, body: dispute as unknown as Json };
    });
  }

  private rDisputeList(auth: { record: AuthRecord }, inb: Inbound): DoResponse {
    const q = parseQuery(inb.path);
    const afterN = parseUintParam(q.get("after_seq") ?? "0");
    const limitN = parseUintParam(q.get("limit") ?? "100");
    if (limitN < 1 || limitN > 100) throw new BedrockError("SCHEMA", "limit outside [1,100]");
    const actorFilter = auth.record.role === "agent" ? auth.record.principal_id : null;
    const rows = this.deps.store.disputesPage(afterN, limitN, actorFilter);
    const page = rows.slice(0, limitN);
    const disputes = page.map((r) => JSON.parse(Buffer.from(r.record_jcs).toString("utf8")) as Dispute);
    const more = rows.length > limitN;
    return {
      status: 200,
      body: {
        disputes: disputes as unknown as Json,
        next_after: more && page.length > 0 ? page[page.length - 1]!.receipt_seq : null,
      } as unknown as Json,
    };
  }

  // --- fleet -------------------------------------------------------------------------

  private rHeartbeat(
    auth: { record: AuthRecord; principal: Principal }, inb: Inbound, body: Json,
  ): Promise<DoResponse> {
    const req = vHeartbeat(body);
    // Credential-bound instance check precedes idempotency: a heartbeat for an
    // instance the credential is not bound to is indistinguishable NOT_FOUND,
    // even when its request_id collides with a prior stored request.
    if (req.instance_id !== auth.record.instance_id) {
      throw new BedrockError("NOT_FOUND", "instance not bound to credential");
    }
    if (!this.deps.config.instance_inventory.includes(req.instance_id)) {
      throw new BedrockError("NOT_FOUND", "instance not in inventory");
    }
    return this.mutating(auth, inb, body, req.request_id, "fleet.heartbeat", false, () => {
      const inst = this.deps.store.getInstance(req.instance_id);
      if (!inst) throw new BedrockError("NOT_FOUND", "instance not in inventory");
      if (req.counter !== inst.counter + 1) {
        throw new BedrockError("COUNTER_CONFLICT", "heartbeat counter must be sequential");
      }
      const now = this.authorityNow();
      const view = JSON.parse(Buffer.from(inst.view_jcs).toString("utf8")) as InstanceView;
      const prevFresh = inst.received_ms !== null && now < inst.received_ms + HEARTBEAT_FRESH_MS;
      const from: InstanceState = prevFresh ? view.state : "MISSING";
      const pin = this.activePin();
      const to: InstanceState =
        pin !== null && req.observed_pin !== null &&
        canonicalEqual(req.observed_pin, pin) && req.manifest_hash === pin.manifest_hash
          ? "MATCHED"
          : "MISMATCH";
      const newView: InstanceView = {
        instance_id: req.instance_id, counter: req.counter,
        received_at: nowTime(now), expires_at: nowTime(now + HEARTBEAT_FRESH_MS),
        observed_pin: req.observed_pin, manifest_hash: req.manifest_hash, state: to,
      };
      this.deps.store.putInstance(req.instance_id, req.counter, now, J(newView as unknown as Json));
      let seq: number | null = null;
      if (from !== to) {
        seq = this.appendAudit(auth.record.principal_id, req.instance_id, pin, {
          type: "FleetStatusChanged",
          value: { instance_id: req.instance_id, from, to, counter: req.counter },
        });
      }
      const result = {
        counter: req.counter, expires_at: nowTime(now + HEARTBEAT_FRESH_MS),
        state: to, audit_seq: seq,
      } as unknown as Json;
      this.storeIdempotent(auth.record.principal_id, req.request_id, "fleet.heartbeat", inb.method, inb.path, body, 200, result);
      return { status: 200, body: result };
    });
  }

  private rFleet(): DoResponse {
    const now = this.now();
    const pin = this.activePin();
    const instances: InstanceView[] = this.deps.store.allInstances().map((inst) => {
      const view = JSON.parse(Buffer.from(inst.view_jcs).toString("utf8")) as InstanceView;
      const fresh = inst.received_ms !== null && now < inst.received_ms + HEARTBEAT_FRESH_MS;
      return { ...view, state: fresh ? view.state : ("MISSING" as InstanceState) };
    });
    let status: Fleet["status"];
    if (pin === null) status = "EMPTY";
    else if (instances.some((i) => i.state === "MISMATCH")) status = "SPLIT";
    else if (instances.some((i) => i.state === "MISSING")) status = "MISSING";
    else status = "HEALTHY";
    const fleet: Fleet = { as_of: nowTime(now), desired_pin: pin, status, instances };
    return { status: 200, body: fleet as unknown as Json };
  }

  // --- audit ---------------------------------------------------------------------------

  private rAudit(inb: Inbound): DoResponse {
    const q = parseQuery(inb.path);
    const afterN = parseUintParam(q.get("after_seq") ?? "0");
    const throughRaw = q.get("through_seq");
    if (throughRaw === undefined) throw new BedrockError("SCHEMA", "through_seq is required");
    const throughN = parseUintParam(throughRaw);
    const limitN = parseUintParam(q.get("limit") ?? "100");
    if (limitN < 1 || limitN > 100) throw new BedrockError("SCHEMA", "limit outside [1,100]");
    const head = this.deps.store.auditHeadSeq();
    if (throughN > head) throw new BedrockError("SCHEMA", "through_seq exceeds head");
    if (throughN < afterN) throw new BedrockError("SCHEMA", "through_seq < after_seq");
    const rows = this.deps.store.auditRange(afterN, throughN, limitN);
    const entries: AuditEntry[] = rows.map((r) => ({
      body: JSON.parse(Buffer.from(r.body_jcs).toString("utf8")) as AuditBody,
      hash: r.hash, key_id: r.key_id, signature: r.signature,
    }));
    const more = rows.length === limitN && rows.length > 0 && rows[rows.length - 1]!.seq < throughN;
    const pinSeqs = entries.filter((e) => e.body.event.type === "PinActivated").map((e) => e.body.seq);
    const updates = this.deps.store.pinUpdatesByAuditSeqs(pinSeqs);
    if (pinSeqs.length !== updates.length) {
      throw new BedrockError("AUDIT_UNAVAILABLE", "retained pin update bytes missing");
    }
    const pinUpdates = updates
      .map((x) => JSON.parse(Buffer.from(x.signed_update_jcs).toString("utf8")) as SignedPinUpdate)
      .sort((a, b) => a.update.expected_revision - b.update.expected_revision);
    return {
      status: 200,
      body: {
        entries: entries as unknown as Json,
        through_seq: throughN,
        next_after: more ? rows[rows.length - 1]!.seq : null,
        pin_updates: pinUpdates as unknown as Json,
      } as unknown as Json,
    };
  }

  private rCheckpoint(inb: Inbound): DoResponse {
    const q = parseQuery(inb.path);
    const raw = q.get("through_seq");
    const head = this.deps.store.auditHeadSeq();
    let n: number;
    if (raw !== undefined) {
      n = parseUintParam(raw);
      const retained = this.deps.store.checkpointAt(n);
      if (retained) {
        return { status: 200, body: JSON.parse(Buffer.from(retained).toString("utf8")) as Json };
      }
      if (n !== head) throw new BedrockError("NOT_FOUND", "historical checkpoint not retained");
    } else {
      n = head;
    }
    return this.deps.store.tx(() => {
      const existing = this.deps.store.checkpointAt(n);
      if (existing) {
        return { status: 200, body: JSON.parse(Buffer.from(existing).toString("utf8")) as Json };
      }
      const key = this.checkpointKeyFor(n + 1);
      const headHash = n === 0 ? ZERO_HASH : this.deps.store.auditEntry(n)!.hash;
      const body2: CheckpointBody = {
        schema: "bedrock.checkpoint/1",
        tenant_id: this.deps.config.tenant_id,
        log_id: this.deps.root.log_id,
        through_seq: n,
        head_hash: headHash,
        time: nowTime(this.authorityNow()),
      };
      const cp = {
        body: body2, key_id: key.key_id,
        signature: b64urlEncode(ed25519Sign(this.deps.secrets.auditSeed, S("checkpoint", body2 as unknown as Json))),
      };
      this.deps.store.insertCheckpoint(n, J(cp as unknown as Json));
      return { status: 200, body: cp as unknown as Json };
    });
  }

  private checkpointKeyFor(seq: number): { key_id: string; public_key: string } {
    const k = this.deps.root.audit_keys.find(
      (a) =>
        a.key_id === this.deps.config.audit_key_id &&
        a.from_seq <= seq && (a.through_seq === null || seq <= a.through_seq),
    );
    if (!k) throw new BedrockError("AUDIT_UNAVAILABLE", "no audit key eligible for checkpoint sequence");
    return k;
  }

  // --- metrics ---------------------------------------------------------------------------

  private rMetrics(): DoResponse {
    if (!this.deps.config.metrics_enabled) throw new BedrockError("NOT_FOUND", "metrics disabled");
    this.touchMetrics();
    const now = this.now();
    const states = this.deps.store.allInstances().map((inst) => {
      const view = JSON.parse(Buffer.from(inst.view_jcs).toString("utf8")) as InstanceView;
      const fresh = inst.received_ms !== null && now < inst.received_ms + HEARTBEAT_FRESH_MS;
      return fresh ? view.state : "MISSING";
    });
    const snap: MetricSnapshot = {
      window_seconds: 60,
      calls: this.metrics.calls,
      allows: this.metrics.allows,
      denies: this.metrics.denies,
      indeterminate: this.metrics.indeterminate,
      audit_failures: this.metrics.audit_failures,
      pin_revision: this.meta().deployment.revision,
      instances_matched: states.filter((s) => s === "MATCHED").length,
      instances_missing: states.filter((s) => s === "MISSING").length,
      instances_mismatch: states.filter((s) => s === "MISMATCH").length,
    };
    return { status: 200, body: snap as unknown as Json };
  }
}

// =============================================================================

/** Post-authorization failures of well-formed mutating commands are audited. */
function isAuditedRejection(code: string): boolean {
  return ![
    "PARSE", "SCHEMA", "LIMIT", "AUTH_REQUIRED", "FORBIDDEN",
    "CLOCK_UNSAFE", "AUDIT_UNAVAILABLE", "STORAGE_FULL",
  ].includes(code);
}

function obj(v: Json, keys: string[]): Record<string, Json> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new BedrockError("SCHEMA", "expected object");
  }
  const o = v as Record<string, Json>;
  const allowed = new Set(keys);
  for (const k of Object.keys(o)) {
    if (!allowed.has(k)) throw new BedrockError("SCHEMA", `undeclared property ${k}`);
  }
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(o, k)) {
      throw new BedrockError("SCHEMA", `missing property ${k}`);
    }
  }
  return o;
}

function vRequestId(v: unknown): string {
  if (typeof v !== "string" || !/^brq_[A-Za-z0-9_-]{21}$/.test(v)) {
    throw new BedrockError("SCHEMA", "bad request_id");
  }
  return v;
}

function parseQuery(path: string): Map<string, string> {
  const i = path.indexOf("?");
  const m = new Map<string, string>();
  if (i === -1) return m;
  for (const part of path.slice(i + 1).split("&")) {
    if (part === "") continue;
    const eq = part.indexOf("=");
    const k = eq === -1 ? part : part.slice(0, eq);
    if (m.has(k)) throw new BedrockError("SCHEMA", "duplicate query parameter");
    m.set(k, eq === -1 ? "" : part.slice(eq + 1));
  }
  return m;
}

function parseUintParam(s: string): number {
  if (!/^(0|[1-9][0-9]*)$/.test(s)) throw new BedrockError("SCHEMA", "bad integer parameter");
  const n = Number(s);
  if (!Number.isSafeInteger(n)) throw new BedrockError("SCHEMA", "integer parameter out of range");
  return n;
}

interface Route {
  name: string;
  roles: string[];
  hasBody: boolean;
  params: Record<string, string>;
}

const ROUTES: { name: string; method: string; pattern: RegExp; roles: string[]; hasBody: boolean; params: string[] }[] = [
  { name: "readyz", method: "GET", pattern: /^\/v1\/readyz$/, roles: ["operator"], hasBody: false, params: [] },
  { name: "charter.validate", method: "POST", pattern: /^\/v1\/charter\/validate$/, roles: ["publisher", "operator"], hasBody: true, params: [] },
  { name: "charter.publish", method: "POST", pattern: /^\/v1\/charter\/publish$/, roles: ["publisher", "operator"], hasBody: true, params: [] },
  { name: "charter.versions", method: "GET", pattern: /^\/v1\/charter\/versions$/, roles: ["reader", "publisher", "operator"], hasBody: false, params: [] },
  { name: "charter.version", method: "GET", pattern: /^\/v1\/charter\/versions\/([0-9]+)$/, roles: ["reader", "publisher", "operator"], hasBody: false, params: ["v"] },
  { name: "deployment.get", method: "GET", pattern: /^\/v1\/deployment$/, roles: ["reader", "operator", "instance"], hasBody: false, params: [] },
  { name: "deployment.pin", method: "POST", pattern: /^\/v1\/deployment\/pin$/, roles: ["operator"], hasBody: true, params: [] },
  { name: "deployment.pause", method: "POST", pattern: /^\/v1\/deployment\/pause$/, roles: ["operator"], hasBody: true, params: [] },
  { name: "gateway.check", method: "POST", pattern: /^\/v1\/gateway\/check$/, roles: ["agent"], hasBody: true, params: [] },
  { name: "gateway.call", method: "POST", pattern: /^\/v1\/gateway\/call$/, roles: ["agent"], hasBody: true, params: [] },
  { name: "gateway.call.get", method: "GET", pattern: /^\/v1\/gateway\/calls\/([^/]+)$/, roles: ["agent", "reader", "operator"], hasBody: false, params: ["id"] },
  { name: "disputes.create", method: "POST", pattern: /^\/v1\/disputes$/, roles: ["agent", "reader", "operator"], hasBody: true, params: [] },
  { name: "disputes.list", method: "GET", pattern: /^\/v1\/disputes$/, roles: ["agent", "reader", "operator"], hasBody: false, params: [] },
  { name: "fleet.heartbeat", method: "POST", pattern: /^\/v1\/fleet\/heartbeat$/, roles: ["instance"], hasBody: true, params: [] },
  { name: "fleet.get", method: "GET", pattern: /^\/v1\/fleet$/, roles: ["reader", "operator", "instance"], hasBody: false, params: [] },
  { name: "audit.list", method: "GET", pattern: /^\/v1\/audit$/, roles: ["reader", "operator"], hasBody: false, params: [] },
  { name: "audit.checkpoint", method: "GET", pattern: /^\/v1\/audit\/checkpoint$/, roles: ["reader", "operator"], hasBody: false, params: [] },
  { name: "metrics", method: "GET", pattern: /^\/v1\/metrics$/, roles: ["operator"], hasBody: false, params: [] },
];

const KNOWN_PATHS = [
  /^\/v1\/readyz$/, /^\/v1\/charter\/validate$/, /^\/v1\/charter\/publish$/,
  /^\/v1\/charter\/versions$/, /^\/v1\/charter\/versions\/[^/]+$/,
  /^\/v1\/deployment$/, /^\/v1\/deployment\/pin$/, /^\/v1\/deployment\/pause$/,
  /^\/v1\/gateway\/check$/, /^\/v1\/gateway\/call$/, /^\/v1\/gateway\/calls\/[^/]+$/,
  /^\/v1\/disputes$/, /^\/v1\/fleet\/heartbeat$/, /^\/v1\/fleet$/,
  /^\/v1\/audit$/, /^\/v1\/audit\/checkpoint$/, /^\/v1\/metrics$/, /^\/healthz$/,
];

const QUERY_ALLOW: Record<string, string[]> = {
  "charter.versions": ["after", "limit"],
  "disputes.list": ["after_seq", "limit"],
  "audit.list": ["after_seq", "through_seq", "limit"],
  "audit.checkpoint": ["through_seq"],
};

function matchRoute(method: string, path: string): Route | null {
  const pathOnly = path.split("?")[0]!;
  for (const r of ROUTES) {
    const m = r.pattern.exec(pathOnly);
    if (m && r.method === method) {
      const params: Record<string, string> = {};
      r.params.forEach((p, i) => (params[p] = m[i + 1]!));
      checkQueryAllowed(r.name, path);
      return { name: r.name, roles: r.roles, hasBody: r.hasBody, params };
    }
  }
  return null;
}

function checkQueryAllowed(route: string, path: string): void {
  const i = path.indexOf("?");
  if (i === -1) return;
  const allowed = new Set(QUERY_ALLOW[route] ?? []);
  const seen = new Set<string>();
  for (const part of path.slice(i + 1).split("&")) {
    if (part === "") throw new BedrockError("SCHEMA", "empty query parameter");
    const k = part.split("=")[0]!;
    if (!allowed.has(k)) throw new BedrockError("SCHEMA", `undeclared query parameter ${k}`);
    if (seen.has(k)) throw new BedrockError("SCHEMA", "duplicate query parameter");
    seen.add(k);
  }
}
