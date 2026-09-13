/**
 * HTTP client SDK (spec §8.2): one-to-one wrappers around the §7 routes.
 * Returns the same body schemas and throws typed ApiError without changing
 * reason codes. No reusable ALLOW token or mutable policy handle exists.
 */
import { parseJsonBytes, canonicalString, type Json } from "./canon.js";
import { BedrockError, type ErrorCode } from "./errors.js";
import type {
  Bundle, CallRequest, CallResult, CheckResult, Deployment, Dispute,
  DisputeRequest, Fleet, Heartbeat, HeartbeatResult, PauseRequest, SignedPinUpdate,
} from "./types.js";

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ErrorCode,
    readonly retryable: boolean,
    readonly auditSeq: number | null,
  ) {
    super(`${code} (HTTP ${status})`);
    this.name = "ApiError";
  }
}

export interface ClientOptions {
  endpoint: string;
  credential: string;
  timeoutMs?: number;
  fetchImpl?: typeof fetch;
}

async function doFetch(
  opts: ClientOptions, method: string, path: string, body: Json | undefined,
): Promise<{ status: number; body: Json }> {
  const f = opts.fetchImpl ?? fetch;
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 10000);
  try {
    const res = await f(new URL(path, opts.endpoint), {
      method,
      headers: {
        authorization: `Bearer ${opts.credential}`,
        ...(body !== undefined ? { "content-type": "application/json" } : {}),
      },
      body: body !== undefined ? canonicalString(body) : undefined,
      signal: ctrl.signal,
      redirect: "error",
    });
    const bytes = new Uint8Array(await res.arrayBuffer());
    let parsed: Json = null;
    if (bytes.length) parsed = parseJsonBytes(bytes);
    if (res.status >= 400) {
      const err = (parsed as { error?: { code?: ErrorCode; retryable?: boolean; audit_seq?: number | null } })?.error;
      throw new ApiError(
        res.status,
        err?.code ?? "AUDIT_UNAVAILABLE",
        err?.retryable ?? false,
        err?.audit_seq ?? null,
      );
    }
    return { status: res.status, body: parsed };
  } finally {
    clearTimeout(t);
  }
}

export class BedrockClient {
  constructor(private opts: ClientOptions) {}

  async readyz() {
    return (await doFetch(this.opts, "GET", "/v1/readyz", undefined)).body;
  }
  async charterValidate(bundle: Bundle) {
    return (await doFetch(this.opts, "POST", "/v1/charter/validate", { bundle: bundle as unknown as Json })).body;
  }
  async charterPublish(requestId: string, bundle: Bundle) {
    return (await doFetch(this.opts, "POST", "/v1/charter/publish", { request_id: requestId, bundle: bundle as unknown as Json })).body;
  }
  async charterVersions(after = 0, limit = 100) {
    return (await doFetch(this.opts, "GET", `/v1/charter/versions?after=${after}&limit=${limit}`, undefined)).body;
  }
  async charterVersion(version: number): Promise<Bundle> {
    return (await doFetch(this.opts, "GET", `/v1/charter/versions/${version}`, undefined)).body as unknown as Bundle;
  }
  async deployment(): Promise<Deployment> {
    return (await doFetch(this.opts, "GET", "/v1/deployment", undefined)).body as unknown as Deployment;
  }
  async pin(update: SignedPinUpdate) {
    return (await doFetch(this.opts, "POST", "/v1/deployment/pin", update as unknown as Json)).body;
  }
  async pause(req: PauseRequest) {
    return (await doFetch(this.opts, "POST", "/v1/deployment/pause", req as unknown as Json)).body;
  }
  async check(request: CallRequest): Promise<CheckResult> {
    return (await doFetch(this.opts, "POST", "/v1/gateway/check", request as unknown as Json)).body as unknown as CheckResult;
  }
  async call(request: CallRequest): Promise<{ status: number; result: CallResult }> {
    const r = await doFetch(this.opts, "POST", "/v1/gateway/call", request as unknown as Json);
    return { status: r.status, result: r.body as unknown as CallResult };
  }
  async callResult(requestId: string): Promise<{ status: number; result: CallResult }> {
    const r = await doFetch(this.opts, "GET", `/v1/gateway/calls/${requestId}`, undefined);
    return { status: r.status, result: r.body as unknown as CallResult };
  }
  async dispute(req: DisputeRequest): Promise<Dispute> {
    return (await doFetch(this.opts, "POST", "/v1/disputes", req as unknown as Json)).body as unknown as Dispute;
  }
  async disputes(afterSeq = 0, limit = 100) {
    return (await doFetch(this.opts, "GET", `/v1/disputes?after_seq=${afterSeq}&limit=${limit}`, undefined)).body;
  }
  async heartbeat(hb: Heartbeat): Promise<HeartbeatResult> {
    return (await doFetch(this.opts, "POST", "/v1/fleet/heartbeat", hb as unknown as Json)).body as unknown as HeartbeatResult;
  }
  async fleet(): Promise<Fleet> {
    return (await doFetch(this.opts, "GET", "/v1/fleet", undefined)).body as unknown as Fleet;
  }
  async audit(afterSeq: number, throughSeq: number, limit = 100) {
    return (await doFetch(
      this.opts, "GET",
      `/v1/audit?after_seq=${afterSeq}&through_seq=${throughSeq}&limit=${limit}`, undefined,
    )).body;
  }
  async checkpoint(throughSeq?: number) {
    const q = throughSeq === undefined ? "" : `?through_seq=${throughSeq}`;
    return (await doFetch(this.opts, "GET", `/v1/audit/checkpoint${q}`, undefined)).body;
  }
  async metrics() {
    return (await doFetch(this.opts, "GET", "/v1/metrics", undefined)).body;
  }
}
