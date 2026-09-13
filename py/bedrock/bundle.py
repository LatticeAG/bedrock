"""Bundle, chain, and signed-pin-update verification (spec §5.2).
Mirrors src/bundle.ts."""
from __future__ import annotations

from .errors import BedrockError
from .canon import canonical_string
from .crypto import D, verify_object
from .schema import v_bundle, v_charter, v_manifest, v_signed_pin_update
from .compiler import (
    check_bundle_semantics, check_lineage, manifest_digest_or_throw, pin_of,
)


def check_signatures(body, kind: str, signatures: list, authority: dict) -> dict:
    """Check one Detached set against an authority (§3.3 ordering rules)."""
    eligible = {k["key_id"]: k["public_key"] for k in authority["keys"]}
    ids = [s["key_id"] for s in signatures]
    if len(set(ids)) != len(ids):
        raise BedrockError("SIGNATURE_DUPLICATE", "duplicate key_id in signatures")
    for i in range(1, len(ids)):
        if ids[i - 1] >= ids[i]:
            raise BedrockError("SCHEMA", "signature entries not sorted by key_id")
    for s in signatures:
        if s["key_id"] not in eligible:
            raise BedrockError("KEY_UNKNOWN", f"key {s['key_id']} not eligible")
    for s in signatures:
        pub = eligible[s["key_id"]]
        if not verify_object(kind, body, pub, s["signature"]):
            raise BedrockError("SIGNATURE_INVALID", f"signature by {s['key_id']} invalid")
    if len(signatures) < authority["threshold"]:
        raise BedrockError("QUORUM", "below threshold")
    return {"signatures": len(signatures), "required": authority["threshold"]}


def verify_bundle(bundle: dict, root: dict, predecessors: list) -> dict:
    """Full chain verification; predecessors in any order, sorted internally."""
    b = v_bundle(bundle)
    v_charter(b["charter"])
    v_manifest(b["manifest"])
    manifest_hash = manifest_digest_or_throw(b["charter"], b["manifest"])

    chain = sorted(predecessors, key=lambda p: p["charter"]["version"])
    if b["charter"]["version"] == 1:
        if chain:
            raise BedrockError("SCHEMA", "genesis bundle with predecessors")
        if b["charter"]["previous_hash"] is not None:
            raise BedrockError("SCHEMA", "genesis previous_hash must be null")
        authority = root["bootstrap"]
    else:
        if len(chain) != b["charter"]["version"] - 1:
            raise BedrockError("HASH_MISMATCH", "incomplete predecessor chain")
        prev = None
        for p in chain:
            _verify_single(p, root, prev)
            prev = p
        pred = chain[-1]
        if pred["charter"]["version"] != b["charter"]["version"] - 1:
            raise BedrockError("VERSION_CONFLICT", "version gap")
        if b["charter"]["previous_hash"] != D("charter", pred["charter"]):
            raise BedrockError(
                "HASH_MISMATCH", "previous_hash does not name predecessor charter hash"
            )
        authority = pred["charter"]["next_authority"]

    counts = check_signatures(b["charter"], "charter", b["signatures"], authority)
    check_bundle_semantics(b["charter"], b["manifest"])
    check_lineage(b["charter"], b["manifest"], root)
    return {
        "valid": True,
        "pin": pin_of(b["charter"], manifest_hash),
        "signatures": counts["signatures"],
        "required": counts["required"],
    }


def _verify_single(bundle: dict, root: dict, predecessor):
    b = v_bundle(bundle)
    v_charter(b["charter"])
    v_manifest(b["manifest"])
    manifest_digest_or_throw(b["charter"], b["manifest"])
    if predecessor is None:
        if b["charter"]["version"] != 1 or b["charter"]["previous_hash"] is not None:
            raise BedrockError("SCHEMA", "bad genesis")
        authority = root["bootstrap"]
    else:
        if b["charter"]["version"] != predecessor["charter"]["version"] + 1:
            raise BedrockError("VERSION_CONFLICT", "version must be predecessor + 1")
        if b["charter"]["previous_hash"] != D("charter", predecessor["charter"]):
            raise BedrockError("HASH_MISMATCH", "previous_hash mismatch")
        authority = predecessor["charter"]["next_authority"]
    check_signatures(b["charter"], "charter", b["signatures"], authority)
    check_bundle_semantics(b["charter"], b["manifest"])
    check_lineage(b["charter"], b["manifest"], root)


def verify_pin_update_signatures(update: dict, authority: dict, tenant_id: str, gateway_id: str):
    u = v_signed_pin_update(update)
    if u["update"]["tenant_id"] != tenant_id or u["update"]["gateway_id"] != gateway_id:
        raise BedrockError("SCHEMA", "pin update tenant/gateway mismatch")
    check_signatures(u["update"], "pin", u["signatures"], authority)


def canonical_equal(a, b) -> bool:
    return canonical_string(a) == canonical_string(b)
