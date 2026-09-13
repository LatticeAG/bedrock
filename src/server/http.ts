/**
 * Local emulator (spec §7.1, `serve --local`): plain-HTTP loopback server that
 * fronts one BedrockTenantDO per tenant. The Worker adapter in worker.ts is
 * the production routing shell; this file exists so the full route surface is
 * exercisable locally without a Cloudflare account.
 */
import { createServer, type Server, type IncomingMessage, type ServerResponse } from "node:http";
import { canonicalString, parseJsonBytes, type Json } from "../canon.js";
import { BedrockError, apiError, httpStatusFor } from "../errors.js";
import { BedrockTenantDO, CrashFault, type Inbound, type DoDeps } from "./tenant.js";

export interface EmulatorOptions {
  host?: string;
  port?: number;
}

export class LocalEmulator {
  private server: Server | null = null;
  /** instanceId: the configured installation instance the emulator binds. */
  constructor(private do_: BedrockTenantDO, private instanceId: string) {}

  get url(): string {
    const addr = this.server?.address();
    if (addr && typeof addr === "object") return `http://127.0.0.1:${addr.port}`;
    return "http://127.0.0.1:0";
  }

  async start(opts: EmulatorOptions = {}): Promise<string> {
    const host = opts.host ?? "127.0.0.1";
    const port = opts.port ?? 0;
    this.server = createServer((req, res) => void this.handle(req, res));
    await new Promise<void>((resolve, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(port, host, resolve);
    });
    return this.url;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    await new Promise<void>((resolve) => this.server!.close(() => resolve()));
    this.server = null;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    const body = chunks.length ? new Uint8Array(Buffer.concat(chunks)) : null;
    const headers: Record<string, string | undefined> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      headers[k.toLowerCase()] = Array.isArray(v) ? v.join(",") : v;
    }
    const inb: Inbound = {
      method: req.method ?? "GET",
      path: req.url ?? "/",
      headers: { ...headers, "x-bedrock-instance": this.instanceId },
      body,
    };
    try {
      const out = await this.do_.fetch(inb);
      res.writeHead(out.status, {
        "content-type": "application/json",
        "cache-control": "no-store",
      });
      res.end(canonicalString(out.body));
    } catch (e) {
      if (e instanceof CrashFault) {
        res.writeHead(500).end();
        return;
      }
      if (e instanceof BedrockError) {
        res.writeHead(httpStatusFor(e.code), {
          "content-type": "application/json",
          "cache-control": "no-store",
        });
        res.end(canonicalString(apiError(e.code, e.auditSeq)));
        return;
      }
      res.writeHead(500, { "content-type": "application/json" });
      res.end(canonicalString(apiError("AUDIT_UNAVAILABLE", null)));
    }
  }
}
