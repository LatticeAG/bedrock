/** Exact data models (spec §4, §9.1). All objects are closed. */
import type { Json } from "./canon.js";

export type Hash = string;
export type Time = string;
export type Signature = string;
export type Label = string;
export type Resource = string;
export type Int = number;
export type Scalar = string | number | boolean;

export type TenantId = string;   // bte_
export type CharterId = string;  // bch_
export type GatewayId = string;  // bgw_
export type InstanceId = string; // bin_
export type PrincipalId = string;// bpr_
export type KeyId = string;      // bky_
export type RequestId = string;  // brq_
export type RuleId = string;     // brl_
export type DisputeId = string;  // bds_
export type LogId = string;      // blg_

export interface PublicKey {
  key_id: KeyId;
  public_key: Hash;
}
export interface Authority {
  threshold: Int;
  keys: PublicKey[];
}
export interface Detached {
  key_id: KeyId;
  signature: Signature;
}
export interface Source {
  repository: string;
  pull_request: Int;
  commit: string;
}
export type Selector =
  | { match: "exact" | "segment_prefix"; value: Resource }
  | { match: "all" };
export type Predicate =
  | { arg: Label; op: "eq"; value: Scalar }
  | { arg: Label; op: "int_lte"; value: Int };
export interface Rule {
  id: RuleId;
  principals: (PrincipalId | "*")[];
  tools: string[];
  scopes: (Label | "*")[];
  resources: Selector[];
  when: Predicate[];
}
export type Field =
  | { name: Label; kind: "string"; max_bytes: Int }
  | { name: Label; kind: "integer"; min: Int; max: Int }
  | { name: Label; kind: "boolean" };
export interface Tool {
  tool: string;
  binding: "RECORDS";
  operation: "get" | "put" | "delete" | "list" | "export";
  args: Field[];
}
export interface Manifest {
  schema: "bedrock.manifest/1";
  gateway_id: GatewayId;
  engine: "bedrock.eval/1";
  resource_grammar: "segments/1";
  adapter_build_hash: Hash;
  tools: Tool[];
}
export interface Charter {
  schema: "bedrock.charter/1";
  tenant_id: TenantId;
  charter_id: CharterId;
  version: Int;
  previous_hash: Hash | null;
  engine: "bedrock.eval/1";
  manifest_hash: Hash;
  issued_at: Time;
  not_before: Time;
  not_after: Time;
  source: Source;
  description: string;
  next_authority: Authority;
  hard_denies: Rule[];
  scope_rules: Rule[];
}
export interface Bundle {
  charter: Charter;
  manifest: Manifest;
  signatures: Detached[];
}
export interface Pin {
  charter_id: CharterId;
  version: Int;
  charter_hash: Hash;
  manifest_hash: Hash;
  engine: "bedrock.eval/1";
}
export interface PinUpdate {
  schema: "bedrock.pin/1";
  tenant_id: TenantId;
  gateway_id: GatewayId;
  request_id: RequestId;
  expected_revision: Int;
  target: Pin;
  expires_at: Time;
}
export interface SignedPinUpdate {
  update: PinUpdate;
  signatures: Detached[];
}

export interface CallRequest {
  request_id: RequestId;
  pin: Pin;
  scope: Label;
  tool: string;
  resource: Resource;
  args: { [field: string]: Scalar };
  deadline: Time;
}
export interface Principal {
  principal_id: PrincipalId;
  scopes: Label[];
}
export interface EvalInput {
  charter: Charter;
  manifest: Manifest;
  active_pin: Pin;
  request: CallRequest;
  principal: Principal;
  now: Time;
}
export type Reason =
  | "ALLOW_SCOPE" | "HARD_DENY" | "NO_SCOPE" | "PIN_MISMATCH"
  | "MANIFEST_MISMATCH" | "CHARTER_NOT_YET_VALID" | "CHARTER_EXPIRED"
  | "DEADLINE" | "PRINCIPAL_SCOPE" | "UNKNOWN_TOOL";
export interface Decision {
  verdict: "ALLOW" | "DENY";
  reason: Reason;
  rule_ids: RuleId[];
}
export interface Deployment {
  gateway_id: GatewayId;
  revision: Int;
  state: "UNPINNED" | "ACTIVE" | "PAUSED";
  pin: Pin | null;
  installed_manifest_hash: Hash;
  in_flight: Int;
}
export type CallState = "DENIED" | "DISPATCHED" | "SUCCEEDED" | "FAILED" | "INDETERMINATE";
export interface CallResult {
  request_id: RequestId;
  state: CallState;
  decision: Decision;
  input_hash: Hash;
  output: Json;
  output_available: boolean;
  output_hash: Hash | null;
  audit_seqs: Int[];
}
export interface CheckResult {
  decision: Decision;
  input_hash: Hash;
  enforcement: false;
  audit_seq: Int;
}
export interface PauseRequest {
  request_id: RequestId;
  expected_revision: Int;
  reason: string;
}
export interface MutationResult {
  revision: Int;
  state: "ACTIVE" | "PAUSED";
  pin: Pin | null;
  in_flight: Int;
  audit_seq: Int;
}

export type DisputeCategory = "POLICY_TEXT" | "SCOPE_MATCH" | "EXECUTION" | "VERSION_SPLIT";
export interface DisputeRequest {
  request_id: RequestId;
  dispute_id: DisputeId;
  pin: Pin;
  audit_seq: Int;
  category: DisputeCategory;
  statement: string;
  evidence_hashes: Hash[];
}
export interface Dispute extends DisputeRequest {
  actor_id: PrincipalId;
  recorded_at: Time;
  status: "RECORDED_ADVISORY";
  receipt_seq: Int;
}
export interface Heartbeat {
  request_id: RequestId;
  instance_id: InstanceId;
  counter: Int;
  observed_pin: Pin | null;
  manifest_hash: Hash;
}
export type InstanceState = "MISSING" | "MATCHED" | "MISMATCH";
export interface InstanceView {
  instance_id: InstanceId;
  counter: Int;
  received_at: Time | null;
  expires_at: Time | null;
  observed_pin: Pin | null;
  manifest_hash: Hash | null;
  state: InstanceState;
}
export interface Fleet {
  as_of: Time;
  desired_pin: Pin | null;
  status: "EMPTY" | "HEALTHY" | "SPLIT" | "MISSING";
  instances: InstanceView[];
}
export interface HeartbeatResult {
  counter: Int;
  expires_at: Time;
  state: InstanceState;
  audit_seq: Int | null;
}

export interface ReceiptRef {
  log_id: LogId;
  seq: Int;
}
export interface DecisionEvent {
  request_id: RequestId;
  input_hash: Hash;
  evaluated_at: Time;
  decision: Decision;
}
export type Event =
  | { type: "CharterPublished"; value: { pin: Pin; source: Source } }
  | { type: "PinActivated"; value: { revision: Int; previous_pin: Pin | null; pin: Pin; update_hash: Hash; in_flight: Int } }
  | { type: "GatewayPaused"; value: { revision: Int; reason: string; in_flight: Int } }
  | { type: "CheckEvaluated" | "CallDenied" | "CallDispatched"; value: DecisionEvent }
  | { type: "CallFinished"; value: { request_id: RequestId; state: "SUCCEEDED" | "FAILED" | "INDETERMINATE"; output_hash: Hash | null } }
  | { type: "DisputeRecorded"; value: { dispute_id: DisputeId; cited_seq: Int; category: DisputeCategory } }
  | { type: "FleetStatusChanged"; value: { instance_id: InstanceId; from: InstanceState; to: InstanceState; counter: Int } }
  | { type: "CommandRejected"; value: { operation: string; code: string; request_hash: Hash } }
  | { type: "StorageMigrated"; value: { from_version: Int; to_version: Int; migration_hash: Hash } };
export interface AuditBody {
  schema: "bedrock.audit/1";
  tenant_id: TenantId;
  log_id: LogId;
  seq: Int;
  prev_hash: Hash;
  time: Time;
  actor_id: PrincipalId;
  subject_id: CharterId | RequestId | DisputeId | InstanceId | LogId;
  policy_pin: Pin | null;
  event: Event;
}
export interface AuditEntry {
  body: AuditBody;
  hash: Hash;
  key_id: KeyId;
  signature: Signature;
}
export interface CheckpointBody {
  schema: "bedrock.checkpoint/1";
  tenant_id: TenantId;
  log_id: LogId;
  through_seq: Int;
  head_hash: Hash;
  time: Time;
}
export interface Checkpoint {
  body: CheckpointBody;
  key_id: KeyId;
  signature: Signature;
}
export interface AuditPage {
  entries: AuditEntry[];
  through_seq: Int;
  next_after: Int | null;
  pin_updates: SignedPinUpdate[];
}
export interface Evidence {
  schema: "bedrock.evidence/1";
  root: RootFile;
  bundles: Bundle[];
  start: Checkpoint | null;
  entries: AuditEntry[];
  pin_updates: SignedPinUpdate[];
  end: Checkpoint;
  inputs: { request: CallRequest; principal: Principal }[];
}
export interface Verification {
  integrity: "VALID" | "INVALID" | "INCOMPLETE";
  replay: "MATCH" | "MISMATCH" | "NOT_REQUESTED" | "INPUTS_MISSING" | "CONTEXT_MISSING";
  through_seq: Int;
  anchored: boolean;
}

export interface AuditKey extends PublicKey {
  from_seq: Int;
  through_seq: Int | null;
}
export interface RootFile {
  schema: "bedrock.root/1";
  tenant_id: TenantId;
  charter_id: CharterId;
  gateway_id: GatewayId;
  log_id: LogId;
  bootstrap: Authority;
  audit_keys: AuditKey[];
}
export interface AuthRecord {
  token_hash: Hash;
  tenant_id: TenantId;
  principal_id: PrincipalId;
  role: "reader" | "publisher" | "operator" | "agent" | "instance";
  scopes: Label[];
  instance_id: InstanceId | null;
  expires_at: Time;
}
export interface ResponseKeys {
  active_key_id: Label;
  keys: { key_id: Label; key_base64url: string }[];
}
export interface Config {
  schema: "bedrock.config/1";
  environment: "local" | "production";
  endpoint: string;
  tenant_id: TenantId;
  gateway_id: GatewayId;
  instance_id: InstanceId;
  system_principal_id: PrincipalId;
  root_file: string;
  manifest_file: string;
  instance_inventory: InstanceId[];
  client_credential_ref: string;
  auth_records_ref: string;
  audit_seed_ref: string;
  audit_key_id: KeyId;
  response_keys_ref: string;
  storage_soft_limit_bytes: Int;
  max_in_flight: Int;
  metrics_enabled: boolean;
}
export interface MetricSnapshot {
  window_seconds: 60;
  calls: Int;
  allows: Int;
  denies: Int;
  indeterminate: Int;
  audit_failures: Int;
  pin_revision: Int;
  instances_matched: Int;
  instances_missing: Int;
  instances_mismatch: Int;
}

export type Warning = "NO_ALLOW_RULES" | "SINGLE_SIGNER" | "EXPIRY_WITHIN_24H";

export interface AdapterRequest {
  request_id: RequestId;
  principal_id: PrincipalId;
  scope: Label;
  pin: Pin;
  input_hash: Hash;
  operation: Tool["operation"];
  resource: Resource;
  args: { [field: string]: Scalar };
  deadline: Time;
}
export type AdapterResponse =
  | { status: "ok" | "error"; output: Json }
  | { status: "unknown" };
