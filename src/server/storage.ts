/**
 * Durable storage for one tenant (spec §10.1). Exact schema; signed JSON is
 * stored as canonical BLOB bytes, never a rewritten representation.
 * Backed by node:sqlite — ":memory:" for tests/emulator, a file otherwise.
 */
import { DatabaseSync } from "node:sqlite";
import { BedrockError } from "../errors.js";
import type { Deployment } from "../types.js";

export const STORAGE_SCHEMA_VERSION = 1;

export const DDL = `
CREATE TABLE meta (singleton INTEGER PRIMARY KEY CHECK(singleton=1), schema_version INTEGER NOT NULL, deployment_jcs BLOB NOT NULL, next_seq INTEGER NOT NULL, head_hash TEXT NOT NULL, last_time_ms INTEGER NOT NULL);
CREATE TABLE charters (version INTEGER PRIMARY KEY, charter_hash TEXT NOT NULL UNIQUE, previous_hash TEXT, bundle_jcs BLOB NOT NULL, published_seq INTEGER NOT NULL UNIQUE);
CREATE TABLE pin_updates (revision INTEGER PRIMARY KEY, update_hash TEXT NOT NULL UNIQUE, signed_update_jcs BLOB NOT NULL, audit_seq INTEGER NOT NULL UNIQUE);
CREATE TABLE requests (principal_id TEXT NOT NULL, request_id TEXT NOT NULL, operation TEXT NOT NULL, body_hash TEXT NOT NULL, response_enc BLOB, response_until_ms INTEGER NOT NULL, result_jcs BLOB NOT NULL, PRIMARY KEY(principal_id,request_id));
CREATE TABLE calls (principal_id TEXT NOT NULL, request_id TEXT NOT NULL, input_hash TEXT NOT NULL, state TEXT NOT NULL, decision_jcs BLOB NOT NULL, deadline_ms INTEGER NOT NULL, output_enc BLOB, output_hash TEXT, audit_seqs_jcs BLOB NOT NULL, PRIMARY KEY(principal_id,request_id));
CREATE TABLE audit (seq INTEGER PRIMARY KEY, hash TEXT NOT NULL UNIQUE, body_jcs BLOB NOT NULL, key_id TEXT NOT NULL, signature TEXT NOT NULL);
CREATE TABLE disputes (dispute_id TEXT PRIMARY KEY, actor_id TEXT NOT NULL, receipt_seq INTEGER NOT NULL UNIQUE, record_jcs BLOB NOT NULL);
CREATE TABLE instances (instance_id TEXT PRIMARY KEY, counter INTEGER NOT NULL, received_ms INTEGER, view_jcs BLOB NOT NULL);
CREATE TABLE checkpoints (through_seq INTEGER PRIMARY KEY, checkpoint_jcs BLOB NOT NULL);
CREATE INDEX calls_pending ON calls(state,deadline_ms);
CREATE INDEX disputes_actor_seq ON disputes(actor_id,receipt_seq);
`;

export class Store {
  readonly db: DatabaseSync;
  private txDepth = 0;

  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec(DDL);
  }

  /** Run fn inside a transaction (BEGIN IMMEDIATE for writers). */
  tx<T>(fn: () => T): T {
    if (this.txDepth > 0) return fn(); // nested: join outer transaction
    this.db.exec("BEGIN IMMEDIATE");
    this.txDepth++;
    try {
      const r = fn();
      this.db.exec("COMMIT");
      return r;
    } catch (e) {
      try {
        this.db.exec("ROLLBACK");
      } catch {
        /* already rolled back */
      }
      throw e;
    } finally {
      this.txDepth--;
    }
  }

  close(): void {
    this.db.close();
  }

  // --- meta ---------------------------------------------------------------
  initMeta(deployment: Deployment): void {
    this.db
      .prepare(
        "INSERT INTO meta (singleton,schema_version,deployment_jcs,next_seq,head_hash,last_time_ms) VALUES (1,?,?,?,?,?)",
      )
      .run(STORAGE_SCHEMA_VERSION, JSON.stringify(deployment), 1, "0".repeat(64), 0);
  }

  getMeta(): {
    schema_version: number;
    deployment: Deployment;
    next_seq: number;
    head_hash: string;
    last_time_ms: number;
  } | null {
    const r = this.db
      .prepare("SELECT schema_version,deployment_jcs,next_seq,head_hash,last_time_ms FROM meta WHERE singleton=1")
      .get() as { schema_version: number; deployment_jcs: Uint8Array; next_seq: number; head_hash: string; last_time_ms: number } | undefined;
    if (!r) return null;
    return {
      schema_version: r.schema_version,
      deployment: JSON.parse(Buffer.from(r.deployment_jcs).toString("utf8")) as Deployment,
      next_seq: r.next_seq,
      head_hash: r.head_hash,
      last_time_ms: r.last_time_ms,
    };
  }

  putMeta(m: { deployment: Deployment; next_seq: number; head_hash: string; last_time_ms: number }): void {
    this.db
      .prepare("UPDATE meta SET deployment_jcs=?,next_seq=?,head_hash=?,last_time_ms=? WHERE singleton=1")
      .run(JSON.stringify(m.deployment), m.next_seq, m.head_hash, m.last_time_ms);
  }

  // --- charters -------------------------------------------------------------
  insertCharter(version: number, charterHash: string, previousHash: string | null, bundleJcs: Uint8Array, publishedSeq: number): void {
    this.db
      .prepare("INSERT INTO charters (version,charter_hash,previous_hash,bundle_jcs,published_seq) VALUES (?,?,?,?,?)")
      .run(version, charterHash, previousHash, Buffer.from(bundleJcs), publishedSeq);
  }
  charterByVersion(version: number): { charter_hash: string; bundle_jcs: Uint8Array; published_seq: number } | null {
    const r = this.db.prepare("SELECT charter_hash,bundle_jcs,published_seq FROM charters WHERE version=?").get(version) as
      | { charter_hash: string; bundle_jcs: Uint8Array; published_seq: number }
      | undefined;
    return r ?? null;
  }
  charterByHash(hash: string): { version: number; bundle_jcs: Uint8Array; published_seq: number } | null {
    const r = this.db.prepare("SELECT version,bundle_jcs,published_seq FROM charters WHERE charter_hash=?").get(hash) as
      | { version: number; bundle_jcs: Uint8Array; published_seq: number }
      | undefined;
    return r ?? null;
  }
  charterHead(): { version: number; charter_hash: string } | null {
    const r = this.db.prepare("SELECT version,charter_hash FROM charters ORDER BY version DESC LIMIT 1").get() as
      | { version: number; charter_hash: string }
      | undefined;
    return r ?? null;
  }
  charterVersions(after: number, limit: number): { version: number; charter_hash: string }[] {
    return this.db
      .prepare("SELECT version,charter_hash FROM charters WHERE version>? ORDER BY version ASC LIMIT ?")
      .all(after, limit) as { version: number; charter_hash: string }[];
  }
  charterCount(): number {
    const r = this.db.prepare("SELECT COUNT(*) AS c FROM charters").get() as { c: number };
    return r.c;
  }

  // --- pin updates ----------------------------------------------------------
  insertPinUpdate(revision: number, updateHash: string, signedUpdateJcs: Uint8Array, auditSeq: number): void {
    this.db
      .prepare("INSERT INTO pin_updates (revision,update_hash,signed_update_jcs,audit_seq) VALUES (?,?,?,?)")
      .run(revision, updateHash, Buffer.from(signedUpdateJcs), auditSeq);
  }
  pinUpdatesByAuditSeqs(seqs: number[]): { audit_seq: number; signed_update_jcs: Uint8Array }[] {
    if (seqs.length === 0) return [];
    const q = `SELECT audit_seq,signed_update_jcs FROM pin_updates WHERE audit_seq IN (${seqs.map(() => "?").join(",")}) ORDER BY audit_seq`;
    return this.db.prepare(q).all(...seqs) as { audit_seq: number; signed_update_jcs: Uint8Array }[];
  }

  // --- requests (idempotency) -----------------------------------------------
  getRequest(principal: string, requestId: string): {
    operation: string; body_hash: string; response_enc: Uint8Array | null;
    response_until_ms: number; result_jcs: Uint8Array | null;
  } | null {
    const r = this.db
      .prepare("SELECT operation,body_hash,response_enc,response_until_ms,result_jcs FROM requests WHERE principal_id=? AND request_id=?")
      .get(principal, requestId) as
      | { operation: string; body_hash: string; response_enc: Uint8Array | null; response_until_ms: number; result_jcs: Uint8Array | null }
      | undefined;
    return r ?? null;
  }
  insertRequest(principal: string, requestId: string, operation: string, bodyHash: string, responseEnc: Uint8Array | null, responseUntilMs: number, resultJcs: Uint8Array): void {
    this.db
      .prepare("INSERT INTO requests (principal_id,request_id,operation,body_hash,response_enc,response_until_ms,result_jcs) VALUES (?,?,?,?,?,?,?)")
      .run(principal, requestId, operation, bodyHash, responseEnc ? Buffer.from(responseEnc) : null, responseUntilMs, Buffer.from(resultJcs));
  }
  updateRequestResponse(principal: string, requestId: string, responseEnc: Uint8Array | null, resultJcs: Uint8Array): void {
    this.db
      .prepare("UPDATE requests SET response_enc=?,result_jcs=? WHERE principal_id=? AND request_id=?")
      .run(responseEnc ? Buffer.from(responseEnc) : null, Buffer.from(resultJcs), principal, requestId);
  }
  expireRequestResponse(principal: string, requestId: string): void {
    this.db
      .prepare("UPDATE requests SET response_enc=NULL WHERE principal_id=? AND request_id=?")
      .run(principal, requestId);
  }

  // --- calls ------------------------------------------------------------------
  getCall(principal: string, requestId: string): {
    input_hash: string; state: string; decision_jcs: Uint8Array; deadline_ms: number;
    output_enc: Uint8Array | null; output_hash: string | null; audit_seqs_jcs: Uint8Array;
  } | null {
    const r = this.db
      .prepare("SELECT input_hash,state,decision_jcs,deadline_ms,output_enc,output_hash,audit_seqs_jcs FROM calls WHERE principal_id=? AND request_id=?")
      .get(principal, requestId) as
      | { input_hash: string; state: string; decision_jcs: Uint8Array; deadline_ms: number; output_enc: Uint8Array | null; output_hash: string | null; audit_seqs_jcs: Uint8Array }
      | undefined;
    return r ?? null;
  }
  insertCall(principal: string, requestId: string, inputHash: string, state: string, decisionJcs: Uint8Array, deadlineMs: number, auditSeqsJcs: Uint8Array): void {
    this.db
      .prepare("INSERT INTO calls (principal_id,request_id,input_hash,state,decision_jcs,deadline_ms,output_enc,output_hash,audit_seqs_jcs) VALUES (?,?,?,?,?,?,NULL,NULL,?)")
      .run(principal, requestId, inputHash, state, Buffer.from(decisionJcs), deadlineMs, Buffer.from(auditSeqsJcs));
  }
  finishCall(principal: string, requestId: string, state: string, outputEnc: Uint8Array | null, outputHash: string | null, auditSeqsJcs: Uint8Array): void {
    this.db
      .prepare("UPDATE calls SET state=?,output_enc=?,output_hash=?,audit_seqs_jcs=? WHERE principal_id=? AND request_id=?")
      .run(state, outputEnc ? Buffer.from(outputEnc) : null, outputHash, Buffer.from(auditSeqsJcs), principal, requestId);
  }
  expireCallOutput(principal: string, requestId: string): void {
    this.db.prepare("UPDATE calls SET output_enc=NULL WHERE principal_id=? AND request_id=?").run(principal, requestId);
  }
  pendingCalls(): { principal_id: string; request_id: string }[] {
    return this.db.prepare("SELECT principal_id,request_id FROM calls WHERE state='DISPATCHED'").all() as { principal_id: string; request_id: string }[];
  }
  callExists(requestId: string): boolean {
    const r = this.db.prepare("SELECT 1 AS x FROM calls WHERE request_id=? LIMIT 1").get(requestId) as { x: number } | undefined;
    return r !== undefined;
  }

  // --- audit ------------------------------------------------------------------
  appendAudit(seq: number, hash: string, bodyJcs: Uint8Array, keyId: string, signature: string): void {
    this.db
      .prepare("INSERT INTO audit (seq,hash,body_jcs,key_id,signature) VALUES (?,?,?,?,?)")
      .run(seq, hash, Buffer.from(bodyJcs), keyId, signature);
  }
  auditEntry(seq: number): { hash: string; body_jcs: Uint8Array; key_id: string; signature: string } | null {
    const r = this.db.prepare("SELECT hash,body_jcs,key_id,signature FROM audit WHERE seq=?").get(seq) as
      | { hash: string; body_jcs: Uint8Array; key_id: string; signature: string }
      | undefined;
    return r ?? null;
  }
  auditRange(after: number, through: number, limit: number): { seq: number; hash: string; body_jcs: Uint8Array; key_id: string; signature: string }[] {
    return this.db
      .prepare("SELECT seq,hash,body_jcs,key_id,signature FROM audit WHERE seq>? AND seq<=? ORDER BY seq ASC LIMIT ?")
      .all(after, through, limit) as { seq: number; hash: string; body_jcs: Uint8Array; key_id: string; signature: string }[];
  }
  auditHeadSeq(): number {
    const r = this.db.prepare("SELECT COALESCE(MAX(seq),0) AS s FROM audit").get() as { s: number };
    return r.s;
  }
  auditCount(): number {
    const r = this.db.prepare("SELECT COUNT(*) AS c FROM audit").get() as { c: number };
    return r.c;
  }

  // --- disputes ----------------------------------------------------------------
  insertDispute(disputeId: string, actorId: string, receiptSeq: number, recordJcs: Uint8Array): void {
    this.db
      .prepare("INSERT INTO disputes (dispute_id,actor_id,receipt_seq,record_jcs) VALUES (?,?,?,?)")
      .run(disputeId, actorId, receiptSeq, Buffer.from(recordJcs));
  }
  disputeById(id: string): { actor_id: string; receipt_seq: number; record_jcs: Uint8Array } | null {
    const r = this.db.prepare("SELECT actor_id,receipt_seq,record_jcs FROM disputes WHERE dispute_id=?").get(id) as
      | { actor_id: string; receipt_seq: number; record_jcs: Uint8Array }
      | undefined;
    return r ?? null;
  }
  disputeByReceiptSeq(seq: number): Uint8Array | null {
    const r = this.db.prepare("SELECT record_jcs FROM disputes WHERE receipt_seq=?").get(seq) as { record_jcs: Uint8Array } | undefined;
    return r ? r.record_jcs : null;
  }
  disputesPage(afterSeq: number, limit: number, actorId: string | null): { receipt_seq: number; record_jcs: Uint8Array }[] {
    if (actorId === null) {
      return this.db
        .prepare("SELECT receipt_seq,record_jcs FROM disputes WHERE receipt_seq>? ORDER BY receipt_seq ASC LIMIT ?")
        .all(afterSeq, limit + 1) as { receipt_seq: number; record_jcs: Uint8Array }[];
    }
    return this.db
      .prepare("SELECT receipt_seq,record_jcs FROM disputes WHERE receipt_seq>? AND actor_id=? ORDER BY receipt_seq ASC LIMIT ?")
      .all(afterSeq, actorId, limit + 1) as { receipt_seq: number; record_jcs: Uint8Array }[];
  }

  // --- instances -----------------------------------------------------------------
  initInstance(instanceId: string, viewJcs: Uint8Array): void {
    this.db
      .prepare("INSERT INTO instances (instance_id,counter,received_ms,view_jcs) VALUES (?,0,NULL,?)")
      .run(instanceId, Buffer.from(viewJcs));
  }
  getInstance(instanceId: string): { counter: number; received_ms: number | null; view_jcs: Uint8Array } | null {
    const r = this.db.prepare("SELECT counter,received_ms,view_jcs FROM instances WHERE instance_id=?").get(instanceId) as
      | { counter: number; received_ms: number | null; view_jcs: Uint8Array }
      | undefined;
    return r ?? null;
  }
  putInstance(instanceId: string, counter: number, receivedMs: number | null, viewJcs: Uint8Array): void {
    this.db
      .prepare("UPDATE instances SET counter=?,received_ms=?,view_jcs=? WHERE instance_id=?")
      .run(counter, receivedMs, Buffer.from(viewJcs), instanceId);
  }
  allInstances(): { instance_id: string; counter: number; received_ms: number | null; view_jcs: Uint8Array }[] {
    return this.db
      .prepare("SELECT instance_id,counter,received_ms,view_jcs FROM instances ORDER BY instance_id ASC")
      .all() as { instance_id: string; counter: number; received_ms: number | null; view_jcs: Uint8Array }[];
  }

  // --- checkpoints -----------------------------------------------------------------
  insertCheckpoint(throughSeq: number, checkpointJcs: Uint8Array): void {
    this.db
      .prepare("INSERT INTO checkpoints (through_seq,checkpoint_jcs) VALUES (?,?)")
      .run(throughSeq, Buffer.from(checkpointJcs));
  }
  checkpointAt(throughSeq: number): Uint8Array | null {
    const r = this.db.prepare("SELECT checkpoint_jcs FROM checkpoints WHERE through_seq=?").get(throughSeq) as
      | { checkpoint_jcs: Uint8Array }
      | undefined;
    return r ? r.checkpoint_jcs : null;
  }

  // --- storage pressure ---------------------------------------------------------
  approximateBytes(): number {
    const r = this.db
      .prepare(
        "SELECT (SELECT COALESCE(SUM(LENGTH(bundle_jcs)),0) FROM charters)+(SELECT COALESCE(SUM(LENGTH(body_jcs)),0) FROM audit)+(SELECT COALESCE(SUM(LENGTH(record_jcs)),0) FROM disputes) AS b",
      )
      .get() as { b: number };
    return r.b;
  }
}

export function storageFailure(e: unknown): never {
  if (e instanceof BedrockError) throw e;
  throw new BedrockError("AUDIT_UNAVAILABLE", `storage failure: ${String(e)}`);
}
