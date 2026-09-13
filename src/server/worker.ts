/**
 * Worker routing shell (spec §2): deliberately a routing stub, not a policy
 * replica. It performs no authorization itself — it resolves the tenant DO,
 * forwards the request with the serving instance bound in the
 * X-Bedrock-Instance header, and returns the DO's exact response.
 *
 * The DO revalidates the bearer credential; a Worker-supplied authentication
 * boolean is never trusted.
 */
import { canonicalString, type Json } from "../canon.js";
import { apiError, BedrockError, httpStatusFor } from "../errors.js";
import type { BedrockTenantDO, Inbound } from "./tenant.js";

export interface WorkerEnv {
  /** Configured installation instance bound into every forwarded request. */
  instance_id: string;
}

export interface WorkerRequest {
  method: string;
  path: string;
  headers: Record<string, string | undefined>;
  body: Uint8Array | null;
}

export interface WorkerResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Route a Worker request to the tenant DO; the DO owns all semantics. */
export async function workerFetch(
  req: WorkerRequest,
  env: WorkerEnv,
  tenant: BedrockTenantDO,
): Promise<WorkerResponse> {
  const inb: Inbound = {
    method: req.method,
    path: req.path,
    headers: { ...req.headers, "x-bedrock-instance": env.instance_id },
    body: req.body,
  };
  try {
    const out = await tenant.fetch(inb);
    return {
      status: out.status,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
      body: canonicalString(out.body),
    };
  } catch (e) {
    if (e instanceof BedrockError) {
      return {
        status: httpStatusFor(e.code),
        headers: { "content-type": "application/json", "cache-control": "no-store" },
        body: canonicalString(apiError(e.code, e.auditSeq)),
      };
    }
    return {
      status: 500,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
      body: canonicalString(apiError("AUDIT_UNAVAILABLE", null)),
    };
  }
}
