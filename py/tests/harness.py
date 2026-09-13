"""Python conformance harness — mirrors tests/harness.ts pure-op semantics."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import bedrock.fixtures as FX
from bedrock.crypto import D


VECTORS_PATH = Path(__file__).resolve().parents[2] / "conformance" / "vectors.jsonl"


def load_vectors() -> list:
    out = []
    for line in VECTORS_PATH.read_text("utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def expand(name: str):
    v = FX.FIXTURES.get(name)
    if v is None:
        raise KeyError(f"unknown fixture {name}")
    return copy.deepcopy(v)


def expand_value(v):
    if isinstance(v, str) and v in FX.FIXTURES:
        return expand(v)
    return v


def apply_set(doc, set_map: dict | None):
    """RFC6901 pointer set on a deep-copied structure."""
    if not set_map:
        return doc
    for pointer, raw_val in set_map.items():
        val = expand_value(raw_val)
        if pointer == "":
            raise ValueError("whole-document set unsupported")
        segs = [
            s.replace("~1", "/").replace("~0", "~")
            for s in pointer[1:].split("/")
        ]
        cur = doc
        for s in segs[:-1]:
            cur = cur[int(s)] if isinstance(cur, list) else cur[s]
            if cur is None:
                raise ValueError(f"bad pointer {pointer}")
        last = segs[-1]
        if isinstance(cur, list):
            cur[int(last)] = val
        else:
            cur[last] = val
    return doc


def resign(kind: str, obj: dict):
    """Re-sign charter/pin-update body with seeds 0 and 1 in key_id order."""
    body = obj["charter"] if kind == "charter" else obj["update"]
    obj["signatures"] = [
        {"key_id": FX.KA, "signature": FX.hex_seed_sign(0, kind, body)},
        {"key_id": FX.KB, "signature": FX.hex_seed_sign(1, kind, body)},
    ]


def eval_fixture(v: dict) -> dict:
    """F.eval with request_patch/charter_patch/principal_patch shallow merges,
    `now` replacement, and `set` RFC6901 patches; charter rehash into pins."""
    inp = json.loads(json.dumps(FX.F["eval"]))
    if "request_patch" in v:
        for k, val in v["request_patch"].items():
            inp["request"][k] = expand_value(val)
    charter_touched = False
    if "charter_patch" in v:
        for k, val in v["charter_patch"].items():
            inp["charter"][k] = expand_value(val)
        charter_touched = True
    if "principal_patch" in v:
        for k, val in v["principal_patch"].items():
            inp["principal"][k] = expand_value(val)
    if "now" in v:
        inp["now"] = v["now"]
    if "set" in v:
        apply_set(inp, v["set"])
        if any(k.startswith("/charter") for k in v["set"]):
            charter_touched = True
    if charter_touched:
        h = D("charter", inp["charter"])
        inp["active_pin"]["charter_hash"] = h
        inp["request"]["pin"] = {**inp["request"]["pin"], "charter_hash": h}
    return inp
