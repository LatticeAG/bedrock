/**
 * The only upstream RPC (spec §9.4): RECORDS.run over five fixed operations.
 * The gateway owns the upstream credential; agents never see it. Adapters must
 * not retry or follow redirects — the gateway's claim is at-most-one invocation.
 */
import { BedrockError } from "../errors.js";
import type { AdapterRequest, AdapterResponse } from "../types.js";
import { vAdapterRequest } from "../schema.js";

export interface RecordsAdapter {
  run(req: AdapterRequest): Promise<AdapterResponse>;
}

/**
 * Conformance fixture adapter (spec §12): `get` returns {value:"ok"}; other
 * operations are simulated and never call real services. Test-only.
 */
export class FixtureRecordsAdapter implements RecordsAdapter {
  dispatches = 0;
  private behavior: ((req: AdapterRequest) => AdapterResponse | Promise<AdapterResponse>) | null = null;

  setBehavior(fn: typeof this.behavior): void {
    this.behavior = fn;
  }

  async run(req: AdapterRequest): Promise<AdapterResponse> {
    this.dispatches++;
    if (this.behavior) return this.behavior(req);
    if (req.operation === "get") return { status: "ok", output: { value: "ok" } };
    return { status: "ok", output: { value: "ok" } };
  }
}

/**
 * In-memory records upstream for the local emulator. Records are scoped per
 * (principal, scope) — the upstream enforces its own data isolation.
 */
export class MemoryRecordsAdapter implements RecordsAdapter {
  private store = new Map<string, string>();

  private key(req: AdapterRequest): string {
    return `${req.principal_id}|${req.scope}|${req.resource}`;
  }

  async run(req: AdapterRequest): Promise<AdapterResponse> {
    vAdapterRequest(req);
    switch (req.operation) {
      case "get": {
        const v = this.store.get(this.key(req));
        if (v === undefined) return { status: "error", output: { code: "RECORD_MISSING" } };
        return { status: "ok", output: { value: v } };
      }
      case "put": {
        this.store.set(this.key(req), String(req.args["value"]));
        return { status: "ok", output: { stored: true } };
      }
      case "delete": {
        const existed = this.store.delete(this.key(req));
        return { status: "ok", output: { deleted: existed } };
      }
      case "list": {
        const limit = Number(req.args["limit"]);
        const prefix = `${req.principal_id}|${req.scope}|`;
        const keys = [...this.store.keys()].filter((k) => k.startsWith(prefix)).slice(0, limit);
        return { status: "ok", output: { keys: keys.map((k) => k.slice(prefix.length)) } };
      }
      case "export":
        return { status: "error", output: { code: "EXPORT_UNSUPPORTED" } };
    }
  }
}
