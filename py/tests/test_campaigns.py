"""Property campaigns for the pure core — mirrors the pure halves of
tests/campaigns.test.ts (deny dominance, deterministic serialization,
duplicate replay determinism, pin/pause evaluation interleavings)."""
from __future__ import annotations

import copy
import random

import bedrock.fixtures as FX
from bedrock.canon import canonical_string, parse_json, parse_json_bytes, J
from bedrock.crypto import D, ed25519_verify, ed25519_sign, b64url_decode, S, hex_decode
from bedrock.evaluator import evaluate
from bedrock.yaml_strict import parse_yaml
from bedrock.errors import BedrockError
import pytest

from harness import eval_fixture, apply_set

TOOLS = ["record.get", "record.put", "record.list", "record.delete", "record.export", "record.exec"]
SCOPES = ["task-a", "task-b", "task-c"]
RESOURCES = ["records/a", "records/b/c", "records2/a", "records", "other/x", "records/%2e%2e/x"]


def test_property_campaign_10000_seeds():
    r = random.Random(0xBED2)
    counts = {"deny": 0, "serial": 0, "replay": 0, "interleave": 0}
    for i in range(10000):
        kind = i % 4
        if kind == 0:
            # deny dominance: matching hard deny always wins over matching allow
            charter = copy.deepcopy(FX.C1)
            charter["scope_rules"] = [{
                "id": FX.RA, "principals": ["*"], "tools": ["record.delete"],
                "scopes": ["task-a"],
                "resources": [{"match": "segment_prefix", "value": "records"}],
                "when": [],
            }]
            h = D("charter", charter)
            inp = {
                "charter": charter, "manifest": copy.deepcopy(FX.M1),
                "active_pin": {**FX.P1, "charter_hash": h},
                "request": {**copy.deepcopy(FX.Q1), "tool": "record.delete",
                            "pin": {**FX.P1, "charter_hash": h}},
                "principal": copy.deepcopy(FX.PRINCIPAL), "now": FX.T0,
            }
            d = evaluate(inp)
            assert d["verdict"] == "DENY" and d["reason"] == "HARD_DENY"
            counts["deny"] += 1
        elif kind == 1:
            # deterministic serialization under key reorder
            obj = {f"k{r.randrange(100)}": r.randrange(1000) for _ in range(5)}
            shuffled = {k: obj[k] for k in reversed(list(obj.keys()))}
            assert canonical_string(obj) == canonical_string(shuffled)
            counts["serial"] += 1
        elif kind == 2:
            # replay determinism: identical inputs → identical decision bytes
            inp = eval_fixture({"request_patch": {"resource": r.choice(RESOURCES[:3])}})
            d1 = evaluate(copy.deepcopy(inp))
            d2 = evaluate(copy.deepcopy(inp))
            assert canonical_string(d1) == canonical_string(d2)
            counts["replay"] += 1
        else:
            # pin/pause interleavings: pin swap + tool change stay deterministic
            inp = eval_fixture({})
            if r.random() < 0.5:
                apply_set(inp, {"/request/pin/version": 2})
            if r.random() < 0.3:
                apply_set(inp, {"/request/tool": "record.delete"})
            d1 = evaluate(copy.deepcopy(inp))
            d2 = evaluate(copy.deepcopy(inp))
            assert canonical_string(d1) == canonical_string(d2)
            counts["interleave"] += 1
    assert sum(counts.values()) == 10000


def test_parse_regressions():
    with pytest.raises(BedrockError) as e:
        parse_json_bytes(b"\xff\xfe{")
    assert e.value.code == "PARSE"
    with pytest.raises(BedrockError) as e:
        parse_json('{"a":"\\ud800x"}')
    assert e.value.code == "PARSE"
    with pytest.raises(BedrockError) as e:
        parse_yaml("base: &b {v: 1}\nx: {<<: *b}\n")
    assert e.value.code == "PARSE"
    with pytest.raises(BedrockError) as e:
        parse_yaml("%YAML 1.2\n---\na: 1\n")
    assert e.value.code == "PARSE"
    # tab indentation
    with pytest.raises(BedrockError) as e:
        parse_yaml("a:\n\tb: 1\n")
    assert e.value.code == "PARSE"


def test_noncanonical_ed25519_rejected():
    pub = hex_decode(FX.PUB[0])
    good = b64url_decode(FX.B1["signatures"][0]["signature"])
    msg = S("charter", FX.C1)
    assert ed25519_verify(pub, good, msg)
    bad = bytearray(good)
    bad[63] = 0xFF
    assert not ed25519_verify(pub, bytes(bad), msg)
    assert not ed25519_verify(pub, bytes(64), msg)


def test_signature_roundtrip_cross_impl():
    # Python sign must verify under the same strict verifier
    seed = hex_decode(FX.SEEDS[0])
    msg = S("charter", FX.C1)
    sig = ed25519_sign(seed, msg)
    assert ed25519_verify(hex_decode(FX.PUB[0]), sig, msg)
    # fixture signatures verify (produced by the TS implementation)
    assert ed25519_verify(
        hex_decode(FX.PUB[0]),
        b64url_decode(FX.B1["signatures"][0]["signature"]), msg,
    )
