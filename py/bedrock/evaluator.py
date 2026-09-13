"""Pure deterministic evaluator (spec §5.1). Mirrors src/evaluator.ts.
Reads no clock; `now` is an input. SCHEMA errors raise BedrockError — parser/
compiler failures are not policy decisions."""
from __future__ import annotations

from .errors import BedrockError
from .crypto import D
from .schema import v_eval_input
from .timeutil import parse_time


def _deny(reason: str, rule_ids=None) -> dict:
    return {"verdict": "DENY", "reason": reason, "rule_ids": rule_ids or []}


def _allow(rule_ids) -> dict:
    return {"verdict": "ALLOW", "reason": "ALLOW_SCOPE", "rule_ids": rule_ids}


def _pin_eq(a: dict, b: dict) -> bool:
    return (
        a["charter_id"] == b["charter_id"]
        and a["version"] == b["version"]
        and a["charter_hash"] == b["charter_hash"]
        and a["manifest_hash"] == b["manifest_hash"]
        and a["engine"] == b["engine"]
    )


def _selector_matches(s: dict, resource: str) -> bool:
    if s["match"] == "all":
        return True
    if s["match"] == "exact":
        return resource == s["value"]
    return resource == s["value"] or resource.startswith(s["value"] + "/")


def _predicate_matches(p: dict, args: dict) -> bool:
    v = args.get(p["arg"])
    if p["op"] == "eq":
        return type(v) is type(p["value"]) and v == p["value"]
    # int_lte: integer arg only
    return isinstance(v, int) and not isinstance(v, bool) and v <= p["value"]


def _rule_matches(r: dict, principal: str, tool: str, scope: str, resource: str, args: dict) -> bool:
    if not (r["principals"][0] == "*" or principal in r["principals"]):
        return False
    if tool not in r["tools"]:
        return False
    if not (r["scopes"][0] == "*" or scope in r["scopes"]):
        return False
    if not any(_selector_matches(s, resource) for s in r["resources"]):
        return False
    return all(_predicate_matches(p, args) for p in r["when"])


def check_args(tool: dict, args: dict):
    """Validate request args exactly against the tool's declared fields."""
    names = {f["name"] for f in tool["args"]}
    for k in args:
        if k not in names:
            raise BedrockError("SCHEMA", f"undeclared arg {k}")
    for f in tool["args"]:
        if f["name"] not in args:
            raise BedrockError("SCHEMA", f"missing arg {f['name']}")
        v = args[f["name"]]
        kind = f["kind"]
        if kind == "string":
            if not isinstance(v, str):
                raise BedrockError("SCHEMA", f"arg {f['name']} must be string")
            if len(v.encode("utf-8")) > f["max_bytes"]:
                raise BedrockError("SCHEMA", f"arg {f['name']} exceeds {f['max_bytes']} bytes")
        elif kind == "integer":
            if not isinstance(v, int) or isinstance(v, bool) or v < f["min"] or v > f["max"]:
                raise BedrockError("SCHEMA", f"arg {f['name']} outside [{f['min']},{f['max']}]")
        elif kind == "boolean":
            if not isinstance(v, bool):
                raise BedrockError("SCHEMA", f"arg {f['name']} must be boolean")


def evaluate(input: dict) -> dict:
    v_eval_input(input)
    charter = input["charter"]
    manifest = input["manifest"]
    active_pin = input["active_pin"]
    request = input["request"]
    principal = input["principal"]
    now_ms = parse_time(input["now"])
    deadline_ms = parse_time(request["deadline"])

    # 1. exact pin equality across all five fields
    if not _pin_eq(request["pin"], active_pin):
        return _deny("PIN_MISMATCH")
    # 2. charter/manifest must equal the active pin and computed manifest
    manifest_hash = D("manifest", manifest)
    if (
        D("charter", charter) != active_pin["charter_hash"]
        or charter["charter_id"] != active_pin["charter_id"]
        or charter["version"] != active_pin["version"]
        or charter["engine"] != active_pin["engine"]
        or manifest_hash != active_pin["manifest_hash"]
    ):
        return _deny("MANIFEST_MISMATCH")
    # 3. charter validity half-open [not_before, not_after)
    if now_ms < parse_time(charter["not_before"]):
        return _deny("CHARTER_NOT_YET_VALID")
    if now_ms >= parse_time(charter["not_after"]):
        return _deny("CHARTER_EXPIRED")
    # 4. deadline: reached or > 30s ahead
    if now_ms >= deadline_ms or deadline_ms - now_ms > 30000:
        return _deny("DEADLINE")
    # 5. request scope must be in the authenticated principal's scope set
    if request["scope"] not in principal["scopes"]:
        return _deny("PRINCIPAL_SCOPE")
    # 6. exact manifest tool name; validate exact args before rule matching
    tool = next((t for t in manifest["tools"] if t["tool"] == request["tool"]), None)
    if tool is None:
        return _deny("UNKNOWN_TOOL")
    check_args(tool, request["args"])
    # 7. hard denies
    deny_ids = sorted(
        r["id"]
        for r in charter["hard_denies"]
        if _rule_matches(r, principal["principal_id"], request["tool"], request["scope"], request["resource"], request["args"])
    )
    if deny_ids:
        return _deny("HARD_DENY", deny_ids)
    # 8. scope rules
    allow_ids = sorted(
        r["id"]
        for r in charter["scope_rules"]
        if _rule_matches(r, principal["principal_id"], request["tool"], request["scope"], request["resource"], request["args"])
    )
    if allow_ids:
        return _allow(allow_ids)
    # 9. default deny
    return _deny("NO_SCOPE")
