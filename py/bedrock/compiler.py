"""Semantic compiler checks (spec §4.1, §5.2). Mirrors src/compiler.ts."""
from __future__ import annotations

from .errors import BedrockError
from .canon import canonical_string
from .crypto import D
from .schema import v_charter, v_manifest
from .timeutil import parse_time


def _fail(msg: str):
    raise BedrockError("SCHEMA", msg)


def _check_sorted_unique(values: list, what: str):
    for i in range(1, len(values)):
        if values[i - 1] >= values[i]:
            _fail(f"{what} not sorted/unique")


def _check_sorted_j(values: list, what: str):
    for i in range(1, len(values)):
        if canonical_string(values[i - 1]) >= canonical_string(values[i]):
            _fail(f"{what} not sorted/unique by J bytes")


DAY_MS = 24 * 60 * 60 * 1000
MAX_VALIDITY_MS = 90 * DAY_MS


def check_authority(a: dict):
    if not 1 <= a["threshold"] <= 8:
        _fail("authority threshold outside [1,8]")
    if len(a["keys"]) > 8:
        _fail("authority has more than 8 keys")
    if a["threshold"] > len(a["keys"]):
        _fail("threshold exceeds key count")
    _check_sorted_unique([k["key_id"] for k in a["keys"]], "authority keys")
    pubs = [k["public_key"] for k in a["keys"]]
    if len(set(pubs)) != len(pubs):
        _fail("authority public keys must be distinct")


# The exact v1 RECORDS tool ABI (spec §9.4).
V1_TOOLS = {
    "record.delete": {"operation": "delete", "args": []},
    "record.export": {
        "operation": "export",
        "args": [{"name": "destination", "kind": "string", "max_bytes": 64}],
    },
    "record.get": {"operation": "get", "args": []},
    "record.list": {
        "operation": "list",
        "args": [{"name": "limit", "kind": "integer", "min": 1, "max": 100}],
    },
    "record.put": {
        "operation": "put",
        "args": [{"name": "value", "kind": "string", "max_bytes": 4096}],
    },
}


def _check_manifest_semantics(manifest: dict):
    names = [t["tool"] for t in manifest["tools"]]
    _check_sorted_unique(names, "tools")
    expected = sorted(V1_TOOLS.keys())
    if names != expected:
        _fail("v1 manifest must contain exactly the five record operations")
    for t in manifest["tools"]:
        spec = V1_TOOLS[t["tool"]]
        if t["binding"] != "RECORDS" or t["operation"] != spec["operation"]:
            _fail(f"tool {t['tool']} operation/binding mismatch")
        arg_names = [f["name"] for f in t["args"]]
        _check_sorted_unique(arg_names, "fields")
        if len(t["args"]) != len(spec["args"]) or any(
            canonical_string(f) != canonical_string(spec["args"][i])
            for i, f in enumerate(t["args"])
        ):
            _fail(f"tool {t['tool']} args differ from the v1 record ABI")
        for f in t["args"]:
            if f["kind"] == "integer" and f["min"] > f["max"]:
                _fail(f"field {f['name']} min > max")


def _check_rule(r: dict, deny: bool, manifest: dict, seen: set):
    if r["id"] in seen:
        _fail(f"rule id {r['id']} not unique across rule lists")
    seen.add(r["id"])
    mtools = {t["tool"]: t for t in manifest["tools"]}
    _check_sorted_unique(r["principals"], "principals")
    _check_sorted_unique(r["tools"], "tools")
    _check_sorted_unique(r["scopes"], "scopes")
    _check_sorted_j(r["resources"], "resources")
    _check_sorted_j(r["when"], "predicates")
    if "*" in r["principals"] and len(r["principals"]) != 1:
        _fail("wildcard principal must stand alone")
    if "*" in r["scopes"] and len(r["scopes"]) != 1:
        _fail("wildcard scope must stand alone")
    if not deny:
        if "*" in r["scopes"]:
            _fail("allow rules may not use scope wildcard")
        if any(s["match"] == "all" for s in r["resources"]):
            _fail("allow rules may not use match=all")
    for t in r["tools"]:
        if t not in mtools:
            _fail(f"rule {r['id']} references unknown tool {t}")
    for p in r["when"]:
        ftype = None
        for tn in r["tools"]:
            field = next((a for a in mtools[tn]["args"] if a["name"] == p["arg"]), None)
            if field is None:
                _fail(f"predicate arg {p['arg']} not a field of tool {tn}")
            if ftype is None:
                ftype = field["kind"]
            elif ftype != field["kind"]:
                _fail(f"predicate arg {p['arg']} has inconsistent types across tools")
        if p["op"] == "int_lte" and ftype != "integer":
            _fail(f"int_lte predicate on non-integer arg {p['arg']}")
        if p["op"] == "eq":
            v = p["value"]
            if ftype == "integer" and (not isinstance(v, int) or isinstance(v, bool)):
                _fail("eq predicate type mismatch")
            if ftype == "string" and not isinstance(v, str):
                _fail("eq predicate type mismatch")
            if ftype == "boolean" and not isinstance(v, bool):
                _fail("eq predicate type mismatch")


def _check_charter_semantics(charter: dict, manifest: dict):
    if charter["version"] < 1:
        _fail("version must be >= 1")
    if charter["version"] == 1 and charter["previous_hash"] is not None:
        _fail("genesis requires previous_hash null")
    if charter["version"] > 1 and charter["previous_hash"] is None:
        _fail("successor requires previous_hash")
    issued = parse_time(charter["issued_at"])
    nb = parse_time(charter["not_before"])
    na = parse_time(charter["not_after"])
    if not issued <= nb:
        _fail("issued_at must be <= not_before")
    if not nb < na:
        _fail("not_before must be < not_after")
    if na - nb > MAX_VALIDITY_MS:
        _fail("validity span exceeds 90 days")
    check_authority(charter["next_authority"])
    total = len(charter["hard_denies"]) + len(charter["scope_rules"])
    if total > 128:
        _fail("charter exceeds 128 rules")
    _check_sorted_unique([r["id"] for r in charter["hard_denies"]], "hard_deny rule ids")
    _check_sorted_unique([r["id"] for r in charter["scope_rules"]], "scope rule ids")
    seen: set = set()
    for r in charter["hard_denies"]:
        _check_rule(r, True, manifest, seen)
    for r in charter["scope_rules"]:
        _check_rule(r, False, manifest, seen)


def compile_bundle(charter: dict, manifest: dict) -> dict:
    """Full offline compile: structural schema, manifest digest, semantics."""
    v_charter(charter)
    v_manifest(manifest)
    manifest_hash = manifest_digest_or_throw(charter, manifest)
    _check_manifest_semantics(manifest)
    _check_charter_semantics(charter, manifest)
    return {
        "charter_hash": D("charter", charter),
        "manifest_hash": manifest_hash,
        "engine": "bedrock.eval/1",
    }


def manifest_digest_or_throw(charter: dict, manifest: dict) -> str:
    manifest_hash = D("manifest", manifest)
    if charter["manifest_hash"] != manifest_hash:
        raise BedrockError(
            "HASH_MISMATCH", "charter manifest_hash does not match manifest digest"
        )
    return manifest_hash


def check_bundle_semantics(charter: dict, manifest: dict):
    _check_manifest_semantics(manifest)
    _check_charter_semantics(charter, manifest)


def check_lineage(charter: dict, manifest: dict, root: dict):
    if charter["tenant_id"] != root["tenant_id"]:
        _fail("charter tenant_id does not match root")
    if charter["charter_id"] != root["charter_id"]:
        _fail("charter_id does not match root")
    if manifest["gateway_id"] != root["gateway_id"]:
        _fail("manifest gateway_id does not match root")


def pin_of(charter: dict, manifest_hash: str) -> dict:
    return {
        "charter_id": charter["charter_id"],
        "version": charter["version"],
        "charter_hash": D("charter", charter),
        "manifest_hash": manifest_hash,
        "engine": charter["engine"],
    }
