"""Offline evidence verification (spec §4.4, §8.2, §13.2).
Mirrors src/evidence.ts. Never contacts the registry; never dispatches."""
from __future__ import annotations

from .canon import canonical_string
from .crypto import D, hex_decode, ed25519_verify, b64url_decode, S
from .schema import (
    v_evidence, v_audit_entry, v_checkpoint, v_pin_update,
)
from .evaluator import evaluate
from .bundle import canonical_equal, verify_bundle

ZERO_HASH = "0" * 64


def _invalid(replay, replay_result="NOT_REQUESTED", through_seq=0):
    return {
        "integrity": "INVALID",
        "replay": replay_result,
        "through_seq": through_seq,
        "anchored": False,
    }


def _audit_key_at(root: dict, seq: int):
    for k in root["audit_keys"]:
        if k["from_seq"] <= seq and (k["through_seq"] is None or seq <= k["through_seq"]):
            return k
    return None


def _entry_valid(entry: dict, root: dict) -> bool:
    try:
        v_audit_entry(entry)
    except Exception:
        return False
    key = _audit_key_at(root, entry["body"]["seq"])
    if key is None or key["key_id"] != entry["key_id"]:
        return False
    if D("audit", entry["body"]) != entry["hash"]:
        return False
    try:
        return ed25519_verify(
            hex_decode(key["public_key"]), b64url_decode(entry["signature"]),
            S("audit", entry["body"]),
        )
    except Exception:
        return False


def _checkpoint_valid(cp: dict, root: dict) -> bool:
    try:
        v_checkpoint(cp)
    except Exception:
        return False
    key = _audit_key_at(root, cp["body"]["through_seq"] + 1) or _audit_key_at(
        root, cp["body"]["through_seq"]
    )
    if key is None or key["key_id"] != cp["key_id"]:
        return False
    if cp["body"]["tenant_id"] != root["tenant_id"] or cp["body"]["log_id"] != root["log_id"]:
        return False
    try:
        return ed25519_verify(
            hex_decode(key["public_key"]), b64url_decode(cp["signature"]),
            S("checkpoint", cp["body"]),
        )
    except Exception:
        return False


def _pin_key(p: dict) -> str:
    return canonical_string(p)


def verify_evidence(evidence: dict, root: dict, trusted_checkpoint, replay: bool) -> dict:
    through_seq = 0
    anchored = False

    try:
        v_evidence(evidence)
    except Exception:
        return _invalid(replay)

    # 1. supplied root must equal the caller-pinned root
    if not canonical_equal(evidence["root"], root):
        return _invalid(replay)

    # 2. bundle authority: bundles must verify as a chain under the root
    bundles = sorted(evidence["bundles"], key=lambda b: b["charter"]["version"])
    pins: dict = {}
    try:
        for i, b in enumerate(bundles):
            verify_bundle(b, root, bundles[:i])
            pin = {
                "charter_id": b["charter"]["charter_id"],
                "version": b["charter"]["version"],
                "charter_hash": D("charter", b["charter"]),
                "manifest_hash": D("manifest", b["manifest"]),
                "engine": b["charter"]["engine"],
            }
            pins[_pin_key(pin)] = {"charter": b["charter"], "manifest": b["manifest"]}
    except Exception:
        return {
            "integrity": "INVALID",
            "replay": "CONTEXT_MISSING" if replay else "NOT_REQUESTED",
            "through_seq": 0,
            "anchored": False,
        }

    # 3. start checkpoint
    prev_hash = ZERO_HASH
    expect_seq = 1
    if evidence["start"] is not None:
        if not _checkpoint_valid(evidence["start"], root):
            return {
                "integrity": "INVALID",
                "replay": "CONTEXT_MISSING" if replay else "NOT_REQUESTED",
                "through_seq": 0,
                "anchored": False,
            }
        prev_hash = evidence["start"]["body"]["head_hash"]
        expect_seq = evidence["start"]["body"]["through_seq"] + 1

    # 4. entries: schema → seq → hash → signature → linkage, in order
    integrity = "VALID"
    verified = []
    for e in evidence["entries"]:
        if not _entry_valid(e, root):
            integrity = "INVALID"
            break
        if e["body"]["seq"] != expect_seq or e["body"]["prev_hash"] != prev_hash:
            integrity = "INVALID"
            break
        verified.append(e)
        through_seq = e["body"]["seq"]
        prev_hash = e["hash"]
        expect_seq = e["body"]["seq"] + 1

    # 5. end checkpoint must be valid and name the verified head
    end_ok = False
    if integrity == "VALID":
        if not _checkpoint_valid(evidence["end"], root):
            integrity = "INVALID"
        elif (
            evidence["end"]["body"]["through_seq"] != through_seq
            or evidence["end"]["body"]["head_hash"] != prev_hash
        ):
            integrity = "INCOMPLETE"
        else:
            end_ok = True
    if end_ok and trusted_checkpoint is not None:
        anchored = canonical_equal(evidence["end"], trusted_checkpoint)

    # 6. optional replay
    replay_result = "NOT_REQUESTED"
    if replay and integrity == "VALID":
        replay_result = _replay_decisions(evidence, verified, pins)
    elif replay:
        replay_result = "CONTEXT_MISSING"

    return {
        "integrity": integrity,
        "replay": replay_result,
        "through_seq": through_seq,
        "anchored": anchored,
    }


def _replay_decisions(evidence: dict, entries: list, pins: dict) -> str:
    inputs = {i["request"]["request_id"]: i for i in evidence["inputs"]}
    pin_updates = {}
    for u in evidence["pin_updates"]:
        try:
            v_pin_update(u["update"])
            pin_updates[u["update"]["expected_revision"]] = u
        except Exception:
            return "CONTEXT_MISSING"
    current_pin = None
    for e in entries:
        ev = e["body"]["event"]
        if ev["type"] == "PinActivated":
            current_pin = ev["value"]["pin"]
            continue
        if ev["type"] not in ("CheckEvaluated", "CallDenied", "CallDispatched"):
            continue
        inp = inputs.get(ev["value"]["request_id"])
        if inp is None:
            return "INPUTS_MISSING"
        input_hash = D("input", {"request": inp["request"], "principal": inp["principal"]})
        if input_hash != ev["value"]["input_hash"]:
            return "MISMATCH"
        pin = e["body"]["policy_pin"] or current_pin
        if pin is None:
            return "CONTEXT_MISSING"
        ctx = pins.get(_pin_key(pin))
        if ctx is None:
            return "CONTEXT_MISSING"
        if (
            D("charter", ctx["charter"]) != pin["charter_hash"]
            or D("manifest", ctx["manifest"]) != pin["manifest_hash"]
        ):
            return "CONTEXT_MISSING"
        decision = evaluate({
            "charter": ctx["charter"], "manifest": ctx["manifest"],
            "active_pin": pin, "request": inp["request"],
            "principal": inp["principal"], "now": ev["value"]["evaluated_at"],
        })
        if not canonical_equal(decision, ev["value"]["decision"]):
            return "MISMATCH"
    return "MATCH"
