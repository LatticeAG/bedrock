/**
 * Pure deterministic evaluator (spec §5.1). Reads no clock; `now` is an input.
 * Returns the first failure in the specified order. SCHEMA errors (bad args)
 * raise BedrockError — parser/compiler failures are not policy decisions.
 */
import { BedrockError } from "./errors.js";
import { D } from "./crypto.js";
import { vEvalInput } from "./schema.js";
import type { Decision, EvalInput, Field, Pin, Predicate, Rule, Scalar, Selector, Tool } from "./types.js";

function deny(reason: Decision["reason"], ruleIds: string[] = []): Decision {
  return { verdict: "DENY", reason, rule_ids: ruleIds };
}

function allow(ruleIds: string[]): Decision {
  return { verdict: "ALLOW", reason: "ALLOW_SCOPE", rule_ids: ruleIds };
}

function pinEq(a: Pin, b: Pin): boolean {
  return (
    a.charter_id === b.charter_id &&
    a.version === b.version &&
    a.charter_hash === b.charter_hash &&
    a.manifest_hash === b.manifest_hash &&
    a.engine === b.engine
  );
}

function selectorMatches(s: Selector, resource: string): boolean {
  if (s.match === "all") return true;
  if (s.match === "exact") return resource === s.value;
  // segment_prefix
  return resource === s.value || resource.startsWith(s.value + "/");
}

function predicateMatches(p: Predicate, args: { [f: string]: Scalar }): boolean {
  const v = args[p.arg];
  if (p.op === "eq") {
    return typeof v === typeof p.value && v === p.value;
  }
  // int_lte: integer arg only (typing enforced by schema checks beforehand)
  return typeof v === "number" && Number.isInteger(v) && v <= p.value;
}

function ruleMatches(r: Rule, principal: string, tool: string, scope: string, resource: string, args: { [f: string]: Scalar }): boolean {
  const pOk = r.principals[0] === "*" || r.principals.includes(principal);
  if (!pOk) return false;
  if (!r.tools.includes(tool)) return false;
  const sOk = r.scopes[0] === "*" || r.scopes.includes(scope);
  if (!sOk) return false;
  if (!r.resources.some((s) => selectorMatches(s, resource))) return false;
  return r.when.every((p) => predicateMatches(p, args));
}

/** Validate request args exactly against the tool's declared fields (§4.1). */
export function checkArgs(tool: Tool, args: { [f: string]: Scalar }): void {
  const declared = tool.args;
  const names = new Set(declared.map((f) => f.name));
  for (const k of Object.keys(args)) {
    if (!names.has(k)) throw new BedrockError("SCHEMA", `undeclared arg ${k}`);
  }
  for (const f of declared) {
    if (!Object.prototype.hasOwnProperty.call(args, f.name)) {
      throw new BedrockError("SCHEMA", `missing arg ${f.name}`);
    }
    const v = args[f.name]!;
    switch (f.kind) {
      case "string":
        if (typeof v !== "string") throw new BedrockError("SCHEMA", `arg ${f.name} must be string`);
        if (new TextEncoder().encode(v).length > f.max_bytes) {
          throw new BedrockError("SCHEMA", `arg ${f.name} exceeds ${f.max_bytes} bytes`);
        }
        break;
      case "integer":
        if (typeof v !== "number" || !Number.isInteger(v) || v < f.min || v > f.max) {
          throw new BedrockError("SCHEMA", `arg ${f.name} outside [${f.min},${f.max}]`);
        }
        break;
      case "boolean":
        if (typeof v !== "boolean") throw new BedrockError("SCHEMA", `arg ${f.name} must be boolean`);
        break;
    }
  }
}

export function evaluate(input: EvalInput): Decision {
  vEvalInput(input);
  const { charter, manifest, active_pin, request, principal } = input;
  const nowMs = Date.parse(input.now);
  const deadlineMs = Date.parse(request.deadline);

  // 1. exact pin equality across all five fields
  if (!pinEq(request.pin, active_pin)) return deny("PIN_MISMATCH");
  // 2. charter/manifest must equal the active pin and the computed manifest
  const manifestHash = D("manifest", manifest);
  if (
    D("charter", charter) !== active_pin.charter_hash ||
    charter.charter_id !== active_pin.charter_id ||
    charter.version !== active_pin.version ||
    charter.engine !== active_pin.engine ||
    manifestHash !== active_pin.manifest_hash
  ) {
    return deny("MANIFEST_MISMATCH");
  }
  // 3. charter validity half-open [not_before, not_after)
  if (nowMs < Date.parse(charter.not_before)) return deny("CHARTER_NOT_YET_VALID");
  if (nowMs >= Date.parse(charter.not_after)) return deny("CHARTER_EXPIRED");
  // 4. deadline: reached or > 30s ahead
  if (nowMs >= deadlineMs || deadlineMs - nowMs > 30000) return deny("DEADLINE");
  // 5. request scope must be in the authenticated principal's scope set
  if (!principal.scopes.includes(request.scope)) return deny("PRINCIPAL_SCOPE");
  // 6. exact manifest tool name; validate exact args before rule matching
  const tool = manifest.tools.find((t) => t.tool === request.tool);
  if (!tool) return deny("UNKNOWN_TOOL");
  checkArgs(tool, request.args);
  // 7. hard denies
  const denyIds = charter.hard_denies
    .filter((r) => ruleMatches(r, principal.principal_id, request.tool, request.scope, request.resource, request.args))
    .map((r) => r.id)
    .sort();
  if (denyIds.length > 0) return deny("HARD_DENY", denyIds);
  // 8. scope rules
  const allowIds = charter.scope_rules
    .filter((r) => ruleMatches(r, principal.principal_id, request.tool, request.scope, request.resource, request.args))
    .map((r) => r.id)
    .sort();
  if (allowIds.length > 0) return allow(allowIds);
  // 9. default deny
  return deny("NO_SCOPE");
}
