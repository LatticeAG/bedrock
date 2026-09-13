/**
 * Closed-schema validators (spec §3.1): every declared property required,
 * undeclared properties fail SCHEMA, discriminated unions on literal fields.
 */
import { BedrockError } from "./errors.js";
import type { Json } from "./canon.js";
import { isTime } from "./time.js";
import { b64urlDecode } from "./crypto.js";
import { PREFIXES, type Prefix } from "./ids.js";
import type * as T from "./types.js";

type V<A> = (v: unknown) => A;

function fail(msg: string): never {
  throw new BedrockError("SCHEMA", msg);
}

export function isObj(v: unknown): v is Record<string, Json> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function obj<A>(fields: { [K in keyof A]-?: V<A[K]> }): V<A> {
  const names = new Set(Object.keys(fields));
  return (v: unknown): A => {
    if (!isObj(v)) fail("expected object");
    for (const k of Object.keys(v)) {
      if (!names.has(k)) fail(`undeclared property ${JSON.stringify(k)}`);
    }
    const out: Record<string, unknown> = {};
    for (const k of names) {
      if (!Object.prototype.hasOwnProperty.call(v, k)) fail(`missing property ${k}`);
      out[k] = (fields as Record<string, V<unknown>>)[k]!(v[k]);
    }
    return out as A;
  };
}

function arr<A>(item: V<A>, min = 0, max = Infinity): V<A[]> {
  return (v: unknown): A[] => {
    if (!Array.isArray(v)) fail("expected array");
    if (v.length < min || v.length > max) fail(`array length ${v.length} outside [${min},${max}]`);
    return v.map(item);
  };
}

function union<A>(...vs: V<A>[]): V<A> {
  return (v: unknown): A => {
    for (const f of vs) {
      try {
        return f(v);
      } catch (e) {
        if (e instanceof BedrockError) continue;
        throw e;
      }
    }
    fail("no union variant matched");
  };
}

function lit<A extends Json>(expect: A): V<A> {
  return (v: unknown): A => {
    if (v !== expect) fail(`expected literal ${JSON.stringify(expect)}`);
    return expect;
  };
}

function nul<A>(inner: V<A>): V<A | null> {
  return (v: unknown): A | null => (v === null ? null : inner(v));
}

export const vInt: V<number> = (v: unknown): number => {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0 || v > 9007199254740991 || Object.is(v, -0)) {
    fail("expected Int in [0, 9007199254740991]");
  }
  return v;
};

const vBool: V<boolean> = (v: unknown): boolean => {
  if (typeof v !== "boolean") fail("expected boolean");
  return v;
};

function str(maxBytes?: number, minBytes = 0): V<string> {
  return (v: unknown): string => {
    if (typeof v !== "string") fail("expected string");
    const n = new TextEncoder().encode(v).length;
    if (maxBytes !== undefined && n > maxBytes) fail(`string exceeds ${maxBytes} bytes`);
    if (n < minBytes) fail(`string shorter than ${minBytes} bytes`);
    return v;
  };
}

const HEX64 = /^[0-9a-f]{64}$/;
const vHash: V<string> = (v: unknown): string => {
  if (typeof v !== "string" || !HEX64.test(v)) fail("expected 64 lowercase hex");
  return v;
};

const vTime: V<string> = (v: unknown): string => {
  if (typeof v !== "string" || !isTime(v)) fail("expected Time");
  return v;
};

const LABEL_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const vLabel: V<string> = (v: unknown): string => {
  if (typeof v !== "string" || !LABEL_RE.test(v)) fail("expected Label");
  return v;
};

const TOOL_RE = /^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$/;
export const vToolName: V<string> = (v: unknown): string => {
  if (typeof v !== "string" || !TOOL_RE.test(v)) fail("expected tool name");
  return v;
};

const SEG_RE = /^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$/;
export const vResource: V<string> = (v: unknown): string => {
  if (typeof v !== "string") fail("expected Resource");
  const n = new TextEncoder().encode(v).length;
  if (n < 1 || n > 512) fail("resource length outside [1,512]");
  if (!/^[\x21-\x7e]+$/.test(v)) fail("resource must be printable ASCII");
  if (v.includes("\\") || v.includes("%") || v.includes(":") || v.includes("?") || v.includes("#")) {
    fail("resource contains forbidden syntax");
  }
  const segs = v.split("/");
  for (const s of segs) {
    if (!SEG_RE.test(s) || s === "." || s === "..") fail("bad resource segment");
  }
  return v;
};

const vSignature: V<string> = (v: unknown): string => {
  if (typeof v !== "string") fail("expected Signature");
  try {
    const b = b64urlDecode(v);
    if (b.length !== 64) fail("signature must be 64 bytes");
  } catch (e) {
    if (e instanceof BedrockError && e.code === "PARSE") fail("noncanonical signature encoding");
    throw e;
  }
  return v;
};

function vId(prefix: Prefix): V<string> {
  const re = new RegExp(`^${prefix}_[A-Za-z0-9_-]{21}$`);
  return (v: unknown): string => {
    if (typeof v !== "string" || !re.test(v)) fail(`expected ${prefix}_ id`);
    return v;
  };
}

const SUBJECT_PREFIXES: Prefix[] = ["bch", "brq", "bds", "bin", "blg"];
const vSubjectId: V<string> = (v: unknown): string => {
  if (
    typeof v !== "string" ||
    !new RegExp(`^(${SUBJECT_PREFIXES.join("|")})_[A-Za-z0-9_-]{21}$`).test(v)
  ) {
    fail("expected subject id (bch/brq/bds/bin/blg)");
  }
  return v;
};

const vScalar: V<T.Scalar> = (v: unknown): T.Scalar => {
  if (typeof v === "string") return v;
  if (typeof v === "boolean") return v;
  return vInt(v);
};

const vJson: V<Json> = (v: unknown): Json => {
  if (v === null || typeof v === "boolean" || typeof v === "string") return v;
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v) || Object.is(v, -0)) fail("bad Json number");
    return v;
  }
  if (Array.isArray(v)) return v.map(vJson);
  if (isObj(v)) {
    const o: Record<string, Json> = {};
    for (const k of Object.keys(v)) o[k] = vJson(v[k]);
    return o;
  }
  fail("bad Json value");
};

// ---------------------------------------------------------------------------

const vPublicKey: V<T.PublicKey> = obj<T.PublicKey>({ key_id: vId("bky"), public_key: vHash });

export const vAuthority: V<T.Authority> = obj<T.Authority>({
  threshold: vInt,
  keys: arr(vPublicKey, 1),
});

export const vDetached: V<T.Detached> = obj<T.Detached>({
  key_id: vId("bky"),
  signature: vSignature,
});

const vSource: V<T.Source> = obj<T.Source>({
  repository: (v: unknown): string => {
    if (typeof v !== "string" || !/^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/.test(v)) {
      fail("bad repository");
    }
    return v;
  },
  pull_request: (v: unknown): number => {
    const n = vInt(v);
    if (n < 1 || n > 2147483647) fail("pull_request outside [1,2147483647]");
    return n;
  },
  commit: (v: unknown): string => {
    if (typeof v !== "string" || !/^([0-9a-f]{40}|[0-9a-f]{64})$/.test(v)) fail("bad commit");
    return v;
  },
});

const vSelector: V<T.Selector> = union<T.Selector>(
  obj({ match: lit("exact" as const), value: vResource }) as V<T.Selector>,
  obj({ match: lit("segment_prefix" as const), value: vResource }) as V<T.Selector>,
  obj({ match: lit("all" as const) }) as V<T.Selector>,
);

const vPredicate: V<T.Predicate> = union<T.Predicate>(
  obj({ arg: vLabel, op: lit("eq" as const), value: vScalar }) as V<T.Predicate>,
  obj({ arg: vLabel, op: lit("int_lte" as const), value: vInt }) as V<T.Predicate>,
);

const vRule: V<T.Rule> = obj<T.Rule>({
  id: vId("brl"),
  principals: arr(union<string>(lit("*"), vId("bpr")), 1, 32),
  tools: arr(vToolName, 1, 32),
  scopes: arr(union<string>(lit("*"), vLabel), 1, 32),
  resources: arr(vSelector, 1, 16),
  when: arr(vPredicate, 0, 16),
});

const vField: V<T.Field> = union<T.Field>(
  obj({ name: vLabel, kind: lit("string" as const), max_bytes: (v: unknown): number => {
    const n = vInt(v);
    if (n < 1 || n > 8192) fail("max_bytes outside [1,8192]");
    return n;
  } }) as V<T.Field>,
  obj({ name: vLabel, kind: lit("integer" as const), min: vInt, max: vInt }) as V<T.Field>,
  obj({ name: vLabel, kind: lit("boolean" as const) }) as V<T.Field>,
);

const vTool: V<T.Tool> = obj<T.Tool>({
  tool: vToolName,
  binding: lit("RECORDS" as const),
  operation: union<"get" | "put" | "delete" | "list" | "export">(
    lit("get" as const), lit("put" as const), lit("delete" as const),
    lit("list" as const), lit("export" as const),
  ),
  args: arr(vField, 0, 16),
});

export const vManifest: V<T.Manifest> = obj<T.Manifest>({
  schema: lit("bedrock.manifest/1" as const),
  gateway_id: vId("bgw"),
  engine: lit("bedrock.eval/1" as const),
  resource_grammar: lit("segments/1" as const),
  adapter_build_hash: vHash,
  tools: arr(vTool, 1, 32),
});

export const vCharter: V<T.Charter> = obj<T.Charter>({
  schema: lit("bedrock.charter/1" as const),
  tenant_id: vId("bte"),
  charter_id: vId("bch"),
  version: vInt,
  previous_hash: nul(vHash),
  engine: lit("bedrock.eval/1" as const),
  manifest_hash: vHash,
  issued_at: vTime,
  not_before: vTime,
  not_after: vTime,
  source: vSource,
  description: str(2048, 1),
  next_authority: vAuthority,
  hard_denies: arr(vRule, 0, 128),
  scope_rules: arr(vRule, 0, 128),
});

export const vBundle: V<T.Bundle> = obj<T.Bundle>({
  charter: vCharter,
  manifest: vManifest,
  signatures: arr(vDetached, 1, 8),
});

export const vPin: V<T.Pin> = obj<T.Pin>({
  charter_id: vId("bch"),
  version: vInt,
  charter_hash: vHash,
  manifest_hash: vHash,
  engine: lit("bedrock.eval/1" as const),
});

export const vPinUpdate: V<T.PinUpdate> = obj<T.PinUpdate>({
  schema: lit("bedrock.pin/1" as const),
  tenant_id: vId("bte"),
  gateway_id: vId("bgw"),
  request_id: vId("brq"),
  expected_revision: vInt,
  target: vPin,
  expires_at: vTime,
});

export const vSignedPinUpdate: V<T.SignedPinUpdate> = obj<T.SignedPinUpdate>({
  update: vPinUpdate,
  signatures: arr(vDetached, 1, 8),
});

export const vCallRequest: V<T.CallRequest> = obj<T.CallRequest>({
  request_id: vId("brq"),
  pin: vPin,
  scope: vLabel,
  tool: vToolName,
  resource: vResource,
  args: (v: unknown): { [f: string]: T.Scalar } => {
    if (!isObj(v)) fail("args must be object");
    const out: Record<string, T.Scalar> = {};
    for (const k of Object.keys(v)) {
      if (!LABEL_RE.test(k)) fail(`bad arg field name ${JSON.stringify(k)}`);
      out[k] = vScalar(v[k]);
    }
    return out;
  },
  deadline: vTime,
});

export const vPrincipal: V<T.Principal> = obj<T.Principal>({
  principal_id: vId("bpr"),
  scopes: arr(vLabel, 0),
});

export const vEvalInput: V<T.EvalInput> = obj<T.EvalInput>({
  charter: vCharter,
  manifest: vManifest,
  active_pin: vPin,
  request: vCallRequest,
  principal: vPrincipal,
  now: vTime,
});

const REASONS = [
  "ALLOW_SCOPE", "HARD_DENY", "NO_SCOPE", "PIN_MISMATCH", "MANIFEST_MISMATCH",
  "CHARTER_NOT_YET_VALID", "CHARTER_EXPIRED", "DEADLINE", "PRINCIPAL_SCOPE", "UNKNOWN_TOOL",
] as const;
export const vDecision: V<T.Decision> = obj<T.Decision>({
  verdict: union<"ALLOW" | "DENY">(lit("ALLOW" as const), lit("DENY" as const)),
  reason: union<T.Reason>(...REASONS.map((r) => lit(r))),
  rule_ids: arr(vId("brl"), 0),
});

export const vDeployment: V<T.Deployment> = obj<T.Deployment>({
  gateway_id: vId("bgw"),
  revision: vInt,
  state: union<"UNPINNED" | "ACTIVE" | "PAUSED">(
    lit("UNPINNED" as const), lit("ACTIVE" as const), lit("PAUSED" as const)),
  pin: nul(vPin),
  installed_manifest_hash: vHash,
  in_flight: vInt,
});

export const vPauseRequest: V<T.PauseRequest> = obj<T.PauseRequest>({
  request_id: vId("brq"),
  expected_revision: vInt,
  reason: str(256, 1),
});

export const vDisputeRequest: V<T.DisputeRequest> = obj<T.DisputeRequest>({
  request_id: vId("brq"),
  dispute_id: vId("bds"),
  pin: vPin,
  audit_seq: vInt,
  category: union<T.DisputeCategory>(
    lit("POLICY_TEXT" as const), lit("SCOPE_MATCH" as const),
    lit("EXECUTION" as const), lit("VERSION_SPLIT" as const)),
  statement: str(4096, 1),
  evidence_hashes: arr(vHash, 0, 16),
});

const DISPUTE_REQ_KEYS = vDisputeRequest;
export const vDispute: V<T.Dispute> = (v: unknown): T.Dispute => {
  if (!isObj(v)) fail("expected object");
  const base = DISPUTE_REQ_KEYS(v);
  const extra = obj<{ actor_id: string; recorded_at: string; status: "RECORDED_ADVISORY"; receipt_seq: number }>({
    actor_id: vId("bpr"),
    recorded_at: vTime,
    status: lit("RECORDED_ADVISORY" as const),
    receipt_seq: vInt,
  });
  const e = extra(v);
  const allowed = new Set([
    "request_id", "dispute_id", "pin", "audit_seq", "category", "statement",
    "evidence_hashes", "actor_id", "recorded_at", "status", "receipt_seq",
  ]);
  for (const k of Object.keys(v)) if (!allowed.has(k)) fail(`undeclared property ${k}`);
  return { ...base, ...e };
};

export const vHeartbeat: V<T.Heartbeat> = obj<T.Heartbeat>({
  request_id: vId("brq"),
  instance_id: vId("bin"),
  counter: vInt,
  observed_pin: nul(vPin),
  manifest_hash: vHash,
});

export const vInstanceView: V<T.InstanceView> = obj<T.InstanceView>({
  instance_id: vId("bin"),
  counter: vInt,
  received_at: nul(vTime),
  expires_at: nul(vTime),
  observed_pin: nul(vPin),
  manifest_hash: nul(vHash),
  state: union<T.InstanceState>(lit("MISSING" as const), lit("MATCHED" as const), lit("MISMATCH" as const)),
});

export const vFleet: V<T.Fleet> = obj<T.Fleet>({
  as_of: vTime,
  desired_pin: nul(vPin),
  status: union<"EMPTY" | "HEALTHY" | "SPLIT" | "MISSING">(
    lit("EMPTY" as const), lit("HEALTHY" as const), lit("SPLIT" as const), lit("MISSING" as const)),
  instances: arr(vInstanceView, 0, 32),
});

export const vHeartbeatResult: V<T.HeartbeatResult> = obj<T.HeartbeatResult>({
  counter: vInt,
  expires_at: vTime,
  state: union<T.InstanceState>(lit("MISSING" as const), lit("MATCHED" as const), lit("MISMATCH" as const)),
  audit_seq: nul(vInt),
});

export const vEvent: V<T.Event> = union<T.Event>(
  obj({ type: lit("CharterPublished" as const), value: obj({ pin: vPin, source: vSource }) }) as V<T.Event>,
  obj({ type: lit("PinActivated" as const), value: obj({ revision: vInt, previous_pin: nul(vPin), pin: vPin, update_hash: vHash, in_flight: vInt }) }) as V<T.Event>,
  obj({ type: lit("GatewayPaused" as const), value: obj({ revision: vInt, reason: str(256, 1), in_flight: vInt }) }) as V<T.Event>,
  ...(["CheckEvaluated", "CallDenied", "CallDispatched"] as const).map(
    (t) => obj({ type: lit(t), value: obj<T.DecisionEvent>({ request_id: vId("brq"), input_hash: vHash, evaluated_at: vTime, decision: vDecision }) }) as V<T.Event>,
  ),
  obj({ type: lit("CallFinished" as const), value: obj({ request_id: vId("brq"), state: union<"SUCCEEDED" | "FAILED" | "INDETERMINATE">(lit("SUCCEEDED" as const), lit("FAILED" as const), lit("INDETERMINATE" as const)), output_hash: nul(vHash) }) }) as V<T.Event>,
  obj({ type: lit("DisputeRecorded" as const), value: obj({ dispute_id: vId("bds"), cited_seq: vInt, category: union<T.DisputeCategory>(lit("POLICY_TEXT" as const), lit("SCOPE_MATCH" as const), lit("EXECUTION" as const), lit("VERSION_SPLIT" as const)) }) }) as V<T.Event>,
  obj({ type: lit("FleetStatusChanged" as const), value: obj({ instance_id: vId("bin"), from: union<T.InstanceState>(lit("MISSING" as const), lit("MATCHED" as const), lit("MISMATCH" as const)), to: union<T.InstanceState>(lit("MISSING" as const), lit("MATCHED" as const), lit("MISMATCH" as const)), counter: vInt }) }) as V<T.Event>,
  obj({ type: lit("CommandRejected" as const), value: obj({ operation: str(64, 1), code: str(64, 1), request_hash: vHash }) }) as V<T.Event>,
  obj({ type: lit("StorageMigrated" as const), value: obj({ from_version: vInt, to_version: vInt, migration_hash: vHash }) }) as V<T.Event>,
);

export const vAuditBody: V<T.AuditBody> = obj<T.AuditBody>({
  schema: lit("bedrock.audit/1" as const),
  tenant_id: vId("bte"),
  log_id: vId("blg"),
  seq: vInt,
  prev_hash: vHash,
  time: vTime,
  actor_id: vId("bpr"),
  subject_id: vSubjectId as V<T.AuditBody["subject_id"]>,
  policy_pin: nul(vPin),
  event: vEvent,
});

export const vAuditEntry: V<T.AuditEntry> = obj<T.AuditEntry>({
  body: vAuditBody,
  hash: vHash,
  key_id: vId("bky"),
  signature: vSignature,
});

export const vCheckpointBody: V<T.CheckpointBody> = obj<T.CheckpointBody>({
  schema: lit("bedrock.checkpoint/1" as const),
  tenant_id: vId("bte"),
  log_id: vId("blg"),
  through_seq: vInt,
  head_hash: vHash,
  time: vTime,
});

export const vCheckpoint: V<T.Checkpoint> = obj<T.Checkpoint>({
  body: vCheckpointBody,
  key_id: vId("bky"),
  signature: vSignature,
});

export const vEvidence: V<T.Evidence> = obj<T.Evidence>({
  schema: lit("bedrock.evidence/1" as const),
  root: (v: unknown): T.RootFile => vRootFile(v),
  bundles: arr(vBundle, 0),
  start: nul(vCheckpoint),
  entries: arr(vAuditEntry, 0),
  pin_updates: arr(vSignedPinUpdate, 0),
  end: vCheckpoint,
  inputs: arr(obj({ request: vCallRequest, principal: vPrincipal }), 0),
});

const vAuditKey: V<T.AuditKey> = (v: unknown): T.AuditKey => {
  const k = obj<T.AuditKey>({
    key_id: vId("bky"),
    public_key: vHash,
    from_seq: vInt,
    through_seq: nul(vInt),
  })(v);
  if (k.through_seq !== null && k.through_seq < k.from_seq) fail("audit key range inverted");
  if (k.from_seq < 1) fail("audit key from_seq >= 1");
  return k;
};

export const vRootFile: V<T.RootFile> = obj<T.RootFile>({
  schema: lit("bedrock.root/1" as const),
  tenant_id: vId("bte"),
  charter_id: vId("bch"),
  gateway_id: vId("bgw"),
  log_id: vId("blg"),
  bootstrap: vAuthority,
  audit_keys: arr(vAuditKey, 1, 8),
});

export const vAuthRecord: V<T.AuthRecord> = obj<T.AuthRecord>({
  token_hash: vHash,
  tenant_id: vId("bte"),
  principal_id: vId("bpr"),
  role: union<T.AuthRecord["role"]>(
    lit("reader" as const), lit("publisher" as const), lit("operator" as const),
    lit("agent" as const), lit("instance" as const)),
  scopes: arr(vLabel, 0),
  instance_id: nul(vId("bin")),
  expires_at: vTime,
});

export const vResponseKeys: V<T.ResponseKeys> = obj<T.ResponseKeys>({
  active_key_id: vLabel,
  keys: arr(obj({ key_id: vLabel, key_base64url: (v: unknown): string => {
    if (typeof v !== "string") fail("expected base64url key");
    try {
      const b = b64urlDecode(v);
      if (b.length !== 32) fail("response key must be 32 bytes");
    } catch (e) {
      if (e instanceof BedrockError) fail("bad response key encoding");
      throw e;
    }
    return v;
  } }), 1, 8),
});

const SECRET_REF_RE = /^env:[A-Z][A-Z0-9_]{0,63}$/;
const vSecretRef: V<string> = (v: unknown): string => {
  if (typeof v !== "string" || !SECRET_REF_RE.test(v)) fail("expected env: secret reference");
  return v;
};

export const vConfig: V<T.Config> = obj<T.Config>({
  schema: lit("bedrock.config/1" as const),
  environment: union<"local" | "production">(lit("local" as const), lit("production" as const)),
  endpoint: str(512, 1),
  tenant_id: vId("bte"),
  gateway_id: vId("bgw"),
  instance_id: vId("bin"),
  system_principal_id: vId("bpr"),
  root_file: str(512, 1),
  manifest_file: str(512, 1),
  instance_inventory: arr(vId("bin"), 1, 32),
  client_credential_ref: vSecretRef,
  auth_records_ref: vSecretRef,
  audit_seed_ref: vSecretRef,
  audit_key_id: vId("bky"),
  response_keys_ref: vSecretRef,
  storage_soft_limit_bytes: (v: unknown): number => {
    const n = vInt(v);
    if (n < 1 || n > 8589934592) fail("storage_soft_limit_bytes outside [1, 8GiB]");
    return n;
  },
  max_in_flight: (v: unknown): number => {
    const n = vInt(v);
    if (n < 1 || n > 32) fail("max_in_flight outside [1,32]");
    return n;
  },
  metrics_enabled: vBool,
});

export const vAdapterRequest: V<T.AdapterRequest> = obj<T.AdapterRequest>({
  request_id: vId("brq"),
  principal_id: vId("bpr"),
  scope: vLabel,
  pin: vPin,
  input_hash: vHash,
  operation: union<T.Tool["operation"]>(
    lit("get" as const), lit("put" as const), lit("delete" as const),
    lit("list" as const), lit("export" as const)),
  resource: vResource,
  args: (v: unknown): { [f: string]: T.Scalar } => {
    if (!isObj(v)) fail("args must be object");
    const out: Record<string, T.Scalar> = {};
    for (const k of Object.keys(v)) out[k] = vScalar(v[k]);
    return out;
  },
  deadline: vTime,
});

export const vAdapterResponse: V<T.AdapterResponse> = union<T.AdapterResponse>(
  obj({ status: union<"ok" | "error">(lit("ok" as const), lit("error" as const)), output: vJson }) as V<T.AdapterResponse>,
  obj({ status: lit("unknown" as const) }) as V<T.AdapterResponse>,
);
