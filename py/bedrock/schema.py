"""Closed-schema validators (spec §3.1). Mirrors src/schema.ts: every declared
property required, undeclared properties fail SCHEMA, discriminated unions on
literal fields."""
from __future__ import annotations

import re

from .errors import BedrockError
from .timeutil import is_time
from .crypto import b64url_decode
from .ids import PREFIXES

_SAFE_INT_MAX = 9007199254740991


def _fail(msg: str):
    raise BedrockError("SCHEMA", msg)


def is_obj(v) -> bool:
    return isinstance(v, dict)


def obj(fields: dict):
    names = set(fields.keys())

    def go(v):
        if not is_obj(v):
            _fail("expected object")
        for k in v:
            if k not in names:
                _fail(f"undeclared property {k!r}")
        out = {}
        for k in names:
            if k not in v:
                _fail(f"missing property {k}")
            out[k] = fields[k](v[k])
        return out

    return go


def arr(item, mn=0, mx=None):
    def go(v):
        if not isinstance(v, list):
            _fail("expected array")
        if len(v) < mn or (mx is not None and len(v) > mx):
            _fail(f"array length {len(v)} outside [{mn},{mx if mx is not None else 'inf'}]")
        return [item(e) for e in v]

    return go


def union(*vs):
    def go(v):
        for f in vs:
            try:
                return f(v)
            except BedrockError:
                continue
        _fail("no union variant matched")

    return go


def lit(expect):
    def go(v):
        if v is not expect and v != expect or isinstance(v, bool) != isinstance(expect, bool):
            _fail(f"expected literal {expect!r}")
        return v

    return go


def nul(inner):
    return lambda v: None if v is None else inner(v)


def v_int(v):
    if not isinstance(v, int) or isinstance(v, bool) or v < 0 or v > _SAFE_INT_MAX:
        _fail("expected Int in [0, 9007199254740991]")
    return v


def v_bool(v):
    if not isinstance(v, bool):
        _fail("expected boolean")
    return v


def _str(max_bytes=None, min_bytes=0):
    def go(v):
        if not isinstance(v, str):
            _fail("expected string")
        n = len(v.encode("utf-8"))
        if max_bytes is not None and n > max_bytes:
            _fail(f"string exceeds {max_bytes} bytes")
        if n < min_bytes:
            _fail(f"string shorter than {min_bytes} bytes")
        return v

    return go


HEX64 = re.compile(r"^[0-9a-f]{64}$")


def v_hash(v):
    if not isinstance(v, str) or not HEX64.match(v):
        _fail("expected 64 lowercase hex")
    return v


def v_time(v):
    if not isinstance(v, str) or not is_time(v):
        _fail("expected Time")
    return v


LABEL_RE = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")


def v_label(v):
    if not isinstance(v, str) or not LABEL_RE.match(v):
        _fail("expected Label")
    return v


TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$")


def v_tool_name(v):
    if not isinstance(v, str) or not TOOL_RE.match(v):
        _fail("expected tool name")
    return v


SEG_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}$")


def v_resource(v):
    if not isinstance(v, str):
        _fail("expected Resource")
    n = len(v.encode("utf-8"))
    if n < 1 or n > 512:
        _fail("resource length outside [1,512]")
    if not re.match(r"^[\x21-\x7e]+$", v):
        _fail("resource must be printable ASCII")
    if any(ch in v for ch in ("\\", "%", ":", "?", "#")):
        _fail("resource contains forbidden syntax")
    for s in v.split("/"):
        if not SEG_RE.match(s) or s in (".", ".."):
            _fail("bad resource segment")
    return v


def v_signature(v):
    if not isinstance(v, str):
        _fail("expected Signature")
    try:
        b = b64url_decode(v)
        if len(b) != 64:
            _fail("signature must be 64 bytes")
    except BedrockError as e:
        if e.code == "PARSE":
            _fail("noncanonical signature encoding")
        raise
    return v


def v_id(prefix: str):
    re_id = re.compile(rf"^{prefix}_[A-Za-z0-9_-]{{21}}$")

    def go(v):
        if not isinstance(v, str) or not re_id.match(v):
            _fail(f"expected {prefix}_ id")
        return v

    return go


SUBJECT_PREFIXES = ("bch", "brq", "bds", "bin", "blg")
_SUBJECT_RE = re.compile(
    r"^(" + "|".join(SUBJECT_PREFIXES) + r")_[A-Za-z0-9_-]{21}$"
)


def v_subject_id(v):
    if not isinstance(v, str) or not _SUBJECT_RE.match(v):
        _fail("expected subject id (bch/brq/bds/bin/blg)")
    return v


def v_scalar(v):
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v
    return v_int(v)


def v_json(v):
    if v is None or isinstance(v, bool) or isinstance(v, str):
        return v
    if isinstance(v, int):
        if abs(v) > _SAFE_INT_MAX:
            _fail("bad Json number")
        return v
    if isinstance(v, list):
        return [v_json(e) for e in v]
    if is_obj(v):
        return {k: v_json(e) for k, e in v.items()}
    _fail("bad Json value")


# ---------------------------------------------------------------------------

v_public_key = obj({"key_id": v_id("bky"), "public_key": v_hash})
v_authority = obj({"threshold": v_int, "keys": arr(v_public_key, 1)})
v_detached = obj({"key_id": v_id("bky"), "signature": v_signature})

v_source = obj({
    "repository": lambda v: v
    if isinstance(v, str) and re.match(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$", v)
    else _fail("bad repository"),
    "pull_request": lambda v: (lambda n: n if 1 <= n <= 2147483647 else _fail("pull_request outside [1,2147483647]"))(v_int(v)),
    "commit": lambda v: v
    if isinstance(v, str) and re.match(r"^([0-9a-f]{40}|[0-9a-f]{64})$", v)
    else _fail("bad commit"),
})

v_selector = union(
    obj({"match": lit("exact"), "value": v_resource}),
    obj({"match": lit("segment_prefix"), "value": v_resource}),
    obj({"match": lit("all")}),
)

v_predicate = union(
    obj({"arg": v_label, "op": lit("eq"), "value": v_scalar}),
    obj({"arg": v_label, "op": lit("int_lte"), "value": v_int}),
)

v_rule = obj({
    "id": v_id("brl"),
    "principals": arr(union(lit("*"), v_id("bpr")), 1, 32),
    "tools": arr(v_tool_name, 1, 32),
    "scopes": arr(union(lit("*"), v_label), 1, 32),
    "resources": arr(v_selector, 1, 16),
    "when": arr(v_predicate, 0, 16),
})


def _field_string_max(v):
    n = v_int(v)
    if not 1 <= n <= 8192:
        _fail("max_bytes outside [1,8192]")
    return n


v_field = union(
    obj({"name": v_label, "kind": lit("string"), "max_bytes": _field_string_max}),
    obj({"name": v_label, "kind": lit("integer"), "min": v_int, "max": v_int}),
    obj({"name": v_label, "kind": lit("boolean")}),
)

v_tool = obj({
    "tool": v_tool_name,
    "binding": lit("RECORDS"),
    "operation": union(lit("get"), lit("put"), lit("delete"), lit("list"), lit("export")),
    "args": arr(v_field, 0, 16),
})

v_manifest = obj({
    "schema": lit("bedrock.manifest/1"),
    "gateway_id": v_id("bgw"),
    "engine": lit("bedrock.eval/1"),
    "resource_grammar": lit("segments/1"),
    "adapter_build_hash": v_hash,
    "tools": arr(v_tool, 1, 32),
})

v_charter = obj({
    "schema": lit("bedrock.charter/1"),
    "tenant_id": v_id("bte"),
    "charter_id": v_id("bch"),
    "version": v_int,
    "previous_hash": nul(v_hash),
    "engine": lit("bedrock.eval/1"),
    "manifest_hash": v_hash,
    "issued_at": v_time,
    "not_before": v_time,
    "not_after": v_time,
    "source": v_source,
    "description": _str(2048, 1),
    "next_authority": v_authority,
    "hard_denies": arr(v_rule, 0, 128),
    "scope_rules": arr(v_rule, 0, 128),
})

v_bundle = obj({
    "charter": v_charter,
    "manifest": v_manifest,
    "signatures": arr(v_detached, 1, 8),
})

v_pin = obj({
    "charter_id": v_id("bch"),
    "version": v_int,
    "charter_hash": v_hash,
    "manifest_hash": v_hash,
    "engine": lit("bedrock.eval/1"),
})

v_pin_update = obj({
    "schema": lit("bedrock.pin/1"),
    "tenant_id": v_id("bte"),
    "gateway_id": v_id("bgw"),
    "request_id": v_id("brq"),
    "expected_revision": v_int,
    "target": v_pin,
    "expires_at": v_time,
})

v_signed_pin_update = obj({"update": v_pin_update, "signatures": arr(v_detached, 1, 8)})


def _v_args(v):
    if not is_obj(v):
        _fail("args must be object")
    out = {}
    for k, e in v.items():
        if not LABEL_RE.match(k):
            _fail(f"bad arg field name {k!r}")
        out[k] = v_scalar(e)
    return out


v_call_request = obj({
    "request_id": v_id("brq"),
    "pin": v_pin,
    "scope": v_label,
    "tool": v_tool_name,
    "resource": v_resource,
    "args": _v_args,
    "deadline": v_time,
})

v_principal = obj({"principal_id": v_id("bpr"), "scopes": arr(v_label, 0)})

v_eval_input = obj({
    "charter": v_charter,
    "manifest": v_manifest,
    "active_pin": v_pin,
    "request": v_call_request,
    "principal": v_principal,
    "now": v_time,
})

REASONS = (
    "ALLOW_SCOPE", "HARD_DENY", "NO_SCOPE", "PIN_MISMATCH", "MANIFEST_MISMATCH",
    "CHARTER_NOT_YET_VALID", "CHARTER_EXPIRED", "DEADLINE", "PRINCIPAL_SCOPE",
    "UNKNOWN_TOOL",
)

v_decision = obj({
    "verdict": union(lit("ALLOW"), lit("DENY")),
    "reason": union(*(lit(r) for r in REASONS)),
    "rule_ids": arr(v_id("brl"), 0),
})

v_deployment = obj({
    "gateway_id": v_id("bgw"),
    "revision": v_int,
    "state": union(lit("UNPINNED"), lit("ACTIVE"), lit("PAUSED")),
    "pin": nul(v_pin),
    "installed_manifest_hash": v_hash,
    "in_flight": v_int,
})

v_pause_request = obj({
    "request_id": v_id("brq"),
    "expected_revision": v_int,
    "reason": _str(256, 1),
})

v_dispute_request = obj({
    "request_id": v_id("brq"),
    "dispute_id": v_id("bds"),
    "pin": v_pin,
    "audit_seq": v_int,
    "category": union(
        lit("POLICY_TEXT"), lit("SCOPE_MATCH"), lit("EXECUTION"), lit("VERSION_SPLIT")
    ),
    "statement": _str(4096, 1),
    "evidence_hashes": arr(v_hash, 0, 16),
})

_DISPUTE_ALLOWED = {
    "request_id", "dispute_id", "pin", "audit_seq", "category", "statement",
    "evidence_hashes", "actor_id", "recorded_at", "status", "receipt_seq",
}
_dispute_extra = obj({
    "actor_id": v_id("bpr"),
    "recorded_at": v_time,
    "status": lit("RECORDED_ADVISORY"),
    "receipt_seq": v_int,
})


def v_dispute(v):
    if not is_obj(v):
        _fail("expected object")
    base = v_dispute_request(v)
    e = _dispute_extra(v)
    for k in v:
        if k not in _DISPUTE_ALLOWED:
            _fail(f"undeclared property {k}")
    return {**base, **e}


v_heartbeat = obj({
    "request_id": v_id("brq"),
    "instance_id": v_id("bin"),
    "counter": v_int,
    "observed_pin": nul(v_pin),
    "manifest_hash": v_hash,
})

_instance_state = union(lit("MISSING"), lit("MATCHED"), lit("MISMATCH"))

v_instance_view = obj({
    "instance_id": v_id("bin"),
    "counter": v_int,
    "received_at": nul(v_time),
    "expires_at": nul(v_time),
    "observed_pin": nul(v_pin),
    "manifest_hash": nul(v_hash),
    "state": _instance_state,
})

v_fleet = obj({
    "as_of": v_time,
    "desired_pin": nul(v_pin),
    "status": union(lit("EMPTY"), lit("HEALTHY"), lit("SPLIT"), lit("MISSING")),
    "instances": arr(v_instance_view, 0, 32),
})

v_heartbeat_result = obj({
    "counter": v_int,
    "expires_at": v_time,
    "state": _instance_state,
    "audit_seq": nul(v_int),
})

_decision_event = lambda t: obj({  # noqa: E731
    "type": lit(t),
    "value": obj({
        "request_id": v_id("brq"),
        "input_hash": v_hash,
        "evaluated_at": v_time,
        "decision": v_decision,
    }),
})

v_event = union(
    obj({"type": lit("CharterPublished"), "value": obj({"pin": v_pin, "source": v_source})}),
    obj({"type": lit("PinActivated"), "value": obj({
        "revision": v_int, "previous_pin": nul(v_pin), "pin": v_pin,
        "update_hash": v_hash, "in_flight": v_int,
    })}),
    obj({"type": lit("GatewayPaused"), "value": obj({
        "revision": v_int, "reason": _str(256, 1), "in_flight": v_int,
    })}),
    *(_decision_event(t) for t in ("CheckEvaluated", "CallDenied", "CallDispatched")),
    obj({"type": lit("CallFinished"), "value": obj({
        "request_id": v_id("brq"),
        "state": union(lit("SUCCEEDED"), lit("FAILED"), lit("INDETERMINATE")),
        "output_hash": nul(v_hash),
    })}),
    obj({"type": lit("DisputeRecorded"), "value": obj({
        "dispute_id": v_id("bds"), "cited_seq": v_int,
        "category": union(
            lit("POLICY_TEXT"), lit("SCOPE_MATCH"), lit("EXECUTION"), lit("VERSION_SPLIT")
        ),
    })}),
    obj({"type": lit("FleetStatusChanged"), "value": obj({
        "instance_id": v_id("bin"), "from": _instance_state, "to": _instance_state,
        "counter": v_int,
    })}),
    obj({"type": lit("CommandRejected"), "value": obj({
        "operation": _str(64, 1), "code": _str(64, 1), "request_hash": v_hash,
    })}),
    obj({"type": lit("StorageMigrated"), "value": obj({
        "from_version": v_int, "to_version": v_int, "migration_hash": v_hash,
    })}),
)

v_audit_body = obj({
    "schema": lit("bedrock.audit/1"),
    "tenant_id": v_id("bte"),
    "log_id": v_id("blg"),
    "seq": v_int,
    "prev_hash": v_hash,
    "time": v_time,
    "actor_id": v_id("bpr"),
    "subject_id": v_subject_id,
    "policy_pin": nul(v_pin),
    "event": v_event,
})

v_audit_entry = obj({
    "body": v_audit_body,
    "hash": v_hash,
    "key_id": v_id("bky"),
    "signature": v_signature,
})

v_checkpoint_body = obj({
    "schema": lit("bedrock.checkpoint/1"),
    "tenant_id": v_id("bte"),
    "log_id": v_id("blg"),
    "through_seq": v_int,
    "head_hash": v_hash,
    "time": v_time,
})

v_checkpoint = obj({
    "body": v_checkpoint_body,
    "key_id": v_id("bky"),
    "signature": v_signature,
})

v_evidence = obj({
    "schema": lit("bedrock.evidence/1"),
    "root": lambda v: v_root_file(v),
    "bundles": arr(v_bundle, 0),
    "start": nul(v_checkpoint),
    "entries": arr(v_audit_entry, 0),
    "pin_updates": arr(v_signed_pin_update, 0),
    "end": v_checkpoint,
    "inputs": arr(obj({"request": v_call_request, "principal": v_principal}), 0),
})


def v_audit_key(v):
    k = obj({
        "key_id": v_id("bky"),
        "public_key": v_hash,
        "from_seq": v_int,
        "through_seq": nul(v_int),
    })(v)
    if k["through_seq"] is not None and k["through_seq"] < k["from_seq"]:
        _fail("audit key range inverted")
    if k["from_seq"] < 1:
        _fail("audit key from_seq >= 1")
    return k


v_root_file = obj({
    "schema": lit("bedrock.root/1"),
    "tenant_id": v_id("bte"),
    "charter_id": v_id("bch"),
    "gateway_id": v_id("bgw"),
    "log_id": v_id("blg"),
    "bootstrap": v_authority,
    "audit_keys": arr(v_audit_key, 1, 8),
})

v_auth_record = obj({
    "token_hash": v_hash,
    "tenant_id": v_id("bte"),
    "principal_id": v_id("bpr"),
    "role": union(
        lit("reader"), lit("publisher"), lit("operator"), lit("agent"), lit("instance")
    ),
    "scopes": arr(v_label, 0),
    "instance_id": nul(v_id("bin")),
    "expires_at": v_time,
})


def _v_response_key(v):
    if not isinstance(v, str):
        _fail("expected base64url key")
    try:
        b = b64url_decode(v)
        if len(b) != 32:
            _fail("response key must be 32 bytes")
    except BedrockError as e:
        if e.code == "PARSE":
            _fail("bad response key encoding")
        raise
    return v


v_response_keys = obj({
    "active_key_id": v_label,
    "keys": arr(obj({"key_id": v_label, "key_base64url": _v_response_key}), 1, 8),
})

SECRET_REF_RE = re.compile(r"^env:[A-Z][A-Z0-9_]{0,63}$")


def _v_secret_ref(v):
    if not isinstance(v, str) or not SECRET_REF_RE.match(v):
        _fail("expected env: secret reference")
    return v


def _v_storage_limit(v):
    n = v_int(v)
    if not 1 <= n <= 8589934592:
        _fail("storage_soft_limit_bytes outside [1, 8GiB]")
    return n


def _v_max_in_flight(v):
    n = v_int(v)
    if not 1 <= n <= 32:
        _fail("max_in_flight outside [1,32]")
    return n


v_config = obj({
    "schema": lit("bedrock.config/1"),
    "environment": union(lit("local"), lit("production")),
    "endpoint": _str(512, 1),
    "tenant_id": v_id("bte"),
    "gateway_id": v_id("bgw"),
    "instance_id": v_id("bin"),
    "system_principal_id": v_id("bpr"),
    "root_file": _str(512, 1),
    "manifest_file": _str(512, 1),
    "instance_inventory": arr(v_id("bin"), 1, 32),
    "client_credential_ref": _v_secret_ref,
    "auth_records_ref": _v_secret_ref,
    "audit_seed_ref": _v_secret_ref,
    "audit_key_id": v_id("bky"),
    "response_keys_ref": _v_secret_ref,
    "storage_soft_limit_bytes": _v_storage_limit,
    "max_in_flight": _v_max_in_flight,
    "metrics_enabled": v_bool,
})

v_adapter_request = obj({
    "request_id": v_id("brq"),
    "principal_id": v_id("bpr"),
    "scope": v_label,
    "pin": v_pin,
    "input_hash": v_hash,
    "operation": union(lit("get"), lit("put"), lit("delete"), lit("list"), lit("export")),
    "resource": v_resource,
    "args": _v_args,
    "deadline": v_time,
})
