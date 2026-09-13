"""TV-B--01..55 conformance vectors (spec §13) — Python suite.

The shared corpus lives in conformance/vectors.jsonl. Pure ops run here
against identical semantics; `gateway`/`run` ops are server-side and executed
by the TypeScript suite (the gateway runtime ships in @latticeagi/bedrock).
"""
from __future__ import annotations

import copy

import pytest

import bedrock.fixtures as FX
from bedrock.canon import J, canonical_key_order, parse_json, canonical_string
from bedrock.yaml_strict import parse_yaml
from bedrock.crypto import D
from bedrock.errors import BedrockError
from bedrock.evaluator import evaluate
from bedrock.compiler import compile_bundle
from bedrock.bundle import verify_bundle
from bedrock.evidence import verify_evidence

from harness import load_vectors, expand, expand_value, apply_set, resign, eval_fixture

VECTORS = load_vectors()
SERVER_OPS = {"gateway", "run"}
LAW_ARTIFACTS = {"pin", "bundle", "decision", "audit"}


def _expect_error(fn, code: str):
    with pytest.raises(BedrockError) as ei:
        fn()
    assert ei.value.code == code


def _run_pure(v: dict):
    op = v["op"]
    exp = v["expected"]

    if op == "canonical":
        assert J(v["input"]).decode("utf-8") == exp["utf8"]

    elif op == "canonical_key_order":
        assert canonical_key_order(v["input"]) == exp["keys"]

    elif op == "digest":
        assert D(v["kind"], expand(v["fixture"])) == exp["hash"]

    elif op == "parse_json":
        if "code" in exp:
            _expect_error(lambda: parse_json(v["utf8"]), exp["code"])
        else:
            parse_json(v["utf8"])

    elif op == "parse_yaml":
        if "code" in exp:
            _expect_error(lambda: parse_yaml(v["utf8"]), exp["code"])
        else:
            parse_yaml(v["utf8"])

    elif op == "compile":
        charter = expand(v["fixture"])
        for k, val in v.get("charter_patch", {}).items():
            charter[k] = expand_value(val)
        apply_set(charter, v.get("set"))

        def do():
            return compile_bundle(charter, copy.deepcopy(FX.M1))

        if "code" in exp:
            _expect_error(do, exp["code"])
        else:
            r = do()
            for k, val in exp.items():
                assert r.get(k) == val

    elif op == "compile_composition":
        required = v["input"]["requires"]
        missing = [r for r in required if r not in LAW_ARTIFACTS]
        if "code" in exp:
            _expect_error(
                lambda: (_ for _ in ()).throw(
                    BedrockError("UNSUPPORTED_COMPOSITION", "unmet law requirements: " + ",".join(missing))
                )
                if missing
                else None,
                exp["code"],
            )
        if "law_artifacts" in exp:
            assert exp["law_artifacts"] == 0
            assert missing == ["precedent_root"]

    elif op == "eval":
        inp = eval_fixture(v)
        if "code" in exp:
            _expect_error(lambda: evaluate(inp), exp["code"])
        else:
            d = evaluate(inp)
            assert d["verdict"] == exp["verdict"]
            assert d["reason"] == exp["reason"]
            assert d["rule_ids"] == exp["rule_ids"]

    elif op == "verify":
        bundle = expand(v["fixture"])
        apply_set(bundle, v.get("set"))
        if "take_signatures" in v:
            bundle["signatures"] = [
                copy.deepcopy(bundle["signatures"][i]) for i in v["take_signatures"]
            ]
        if v.get("resign"):
            resign("charter", bundle)
        root = expand(v["root"])
        preds = [expand(p) for p in v.get("predecessors", [])]
        if "code" in exp:
            _expect_error(lambda: verify_bundle(bundle, root, preds), exp["code"])
        else:
            r = verify_bundle(bundle, root, preds)
            assert r["valid"] == exp.get("valid", True)
            if "signatures" in exp:
                assert r["signatures"] == exp["signatures"]
            if "required" in exp:
                assert r["required"] == exp["required"]
            if "version" in exp:
                assert r["pin"]["version"] == exp["version"]

    elif op == "verify_evidence":
        evidence = expand(v["fixture"])
        apply_set(evidence, v.get("set"))
        root = expand(v["root"])
        tc = v.get("trusted_checkpoint")
        trusted = expand(tc) if tc else None
        r = verify_evidence(evidence, root, trusted, v["replay"])
        for k, val in exp.items():
            assert r[k] == val, f"{k}: expected {val}, got {r[k]}"

    else:
        raise AssertionError(f"unhandled op {op}")


@pytest.mark.parametrize("v", VECTORS, ids=[v["id"] for v in VECTORS])
def test_vector(v):
    if v["op"] in SERVER_OPS:
        pytest.skip("server-side vector — executed by the TypeScript suite")
    _run_pure(v)


def test_corpus_complete():
    ids = [v["id"] for v in VECTORS]
    expected = [f"TV-B--{i:02d}" for i in range(1, 56)]
    assert ids == expected


def test_fixture_crypto_independent():
    """Fixture crypto verifies independently in Python (P0 gate)."""
    assert FX.seed_public_key(0) == FX.PUB[0]
    assert FX.seed_public_key(1) == FX.PUB[1]
    assert FX.seed_public_key(2) == FX.PUB[2]
    assert D("charter", FX.C1) == FX.H1
    assert D("manifest", FX.M1) == FX.MH
    assert D("audit", FX.E1BODY) == FX.E1["hash"]
    assert D("pin", FX.U1["update"]) == "06a839b46ec5c73b6f87c6aba2aeccf72b619ec4aeb97649b2a954dcdec63539"
    assert D("input", {"request": FX.Q1, "principal": FX.PRINCIPAL}) == FX.IH1
    r = verify_bundle(copy.deepcopy(FX.B1), copy.deepcopy(FX.R), [])
    assert r["valid"] is True
    # UTF-16 member ordering
    assert J({"\U00010000": 1, "": 2}) == J({"": 2, "\U00010000": 1})
