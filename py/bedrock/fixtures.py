"""Exact §12 fixture corpus. Public test-only RFC8032 seeds — rejected by any
production startup. Mirrors src/fixtures.ts."""
from __future__ import annotations

from .crypto import (
    sha256_hex, hex_decode, ed25519_public_key, ed25519_sign, b64url_encode, S,
)

ID = lambda p, c: f"{p}_{c * 21}"  # noqa: E731

T = ID("bte", "A")
C = ID("bch", "A")
G = ID("bgw", "A")
I = ID("bin", "A")
A = ID("bpr", "A")
O = ID("bpr", "B")
L = ID("blg", "A")
KA = ID("bky", "A")
KB = ID("bky", "B")
KC = ID("bky", "C")
RA = ID("brl", "A")
RD = ID("brl", "D")

T0 = "2026-09-12T00:00:00.000Z"
T30 = "2026-09-12T00:00:30.000Z"
T180 = "2026-09-12T00:03:00.000Z"

SEEDS = (
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
)
PUB = (
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
)

AUTH = {
    "threshold": 2,
    "keys": [
        {"key_id": KA, "public_key": PUB[0]},
        {"key_id": KB, "public_key": PUB[1]},
    ],
}

R = {
    "schema": "bedrock.root/1", "tenant_id": T, "charter_id": C,
    "gateway_id": G, "log_id": L, "bootstrap": AUTH,
    "audit_keys": [
        {"key_id": KC, "public_key": PUB[2], "from_seq": 1, "through_seq": None},
    ],
}

M1 = {
    "schema": "bedrock.manifest/1", "gateway_id": G, "engine": "bedrock.eval/1",
    "resource_grammar": "segments/1",
    "adapter_build_hash": "c4414ed86059305d9902c758cd843f808d07cf057ec7f740d959d4b1538d4bed",
    "tools": [
        {"tool": "record.delete", "binding": "RECORDS", "operation": "delete", "args": []},
        {"tool": "record.export", "binding": "RECORDS", "operation": "export",
         "args": [{"name": "destination", "kind": "string", "max_bytes": 64}]},
        {"tool": "record.get", "binding": "RECORDS", "operation": "get", "args": []},
        {"tool": "record.list", "binding": "RECORDS", "operation": "list",
         "args": [{"name": "limit", "kind": "integer", "min": 1, "max": 100}]},
        {"tool": "record.put", "binding": "RECORDS", "operation": "put",
         "args": [{"name": "value", "kind": "string", "max_bytes": 4096}]},
    ],
}

MH = "c724e7794e18e03c9f3c736d2174566449df0f5ee65b83a0f7c56e6f82023140"
H1 = "cd7f974d91f897bfbe44563ce3b3fdf5e16f2074c6f82569a8727ee313e1d2e7"
H2 = "63eacaa2043c880c20257bf186f15e99208c2c21f08b02df7692c189905ed093"


def _rule(rid, tools):
    return {
        "id": rid, "principals": ["*"], "tools": tools, "scopes": ["task-a"],
        "resources": [{"match": "segment_prefix", "value": "records"}], "when": [],
    }


C1 = {
    "schema": "bedrock.charter/1", "tenant_id": T, "charter_id": C, "version": 1,
    "previous_hash": None, "engine": "bedrock.eval/1", "manifest_hash": MH,
    "issued_at": T0, "not_before": T0, "not_after": "2026-10-12T00:00:00.000Z",
    "source": {
        "repository": "latticeagi/bedrock-policy", "pull_request": 7,
        "commit": "a" * 40,
    },
    "description": "Records within task scope.",
    "next_authority": AUTH,
    "hard_denies": [_rule(RD, ["record.delete"])],
    "scope_rules": [_rule(RA, ["record.get", "record.list", "record.put"])],
}

C2 = {
    **C1, "version": 2, "previous_hash": H1,
    "source": {
        "repository": "latticeagi/bedrock-policy", "pull_request": 8,
        "commit": "b" * 40,
    },
}

P1 = {
    "charter_id": C, "version": 1, "charter_hash": H1, "manifest_hash": MH,
    "engine": "bedrock.eval/1",
}
P2 = {**P1, "version": 2, "charter_hash": H2}

B1 = {
    "charter": C1, "manifest": M1,
    "signatures": [
        {"key_id": KA, "signature": "IiIWmKWQvPUK2Pc_qovNWphNzsbv1ZmLr3PhTbgN5ecIXBWRhYDY0BkuV62OBdOaceXsGlDP6rMyHE3HgTfwDA"},
        {"key_id": KB, "signature": "2lgWcMz6SWa8cW91l8wdTnyxzdgC3VjRCTEniZa2FlepGiTY3tcHxNc7yu4hUHZMgUOfmHhmDS638Lmm3DC5Dw"},
    ],
}

B2 = {
    "charter": C2, "manifest": M1,
    "signatures": [
        {"key_id": KA, "signature": "4sug_aY_vnMlcLWYj6gA5BUdC27PiIkekKvQ3tBtdI5V-ZQ1h68r6MbSSSX3uIPHlKDzXPSdaJz3Wnaki6q_Cw"},
        {"key_id": KB, "signature": "J2HEm0LwaDYCdvJhA638M-oqZ8nxL-8VgrGSEIU9KtrlHkYtofSqpRMS-lmvYPcTUT96liGR4dmZMz9kOrSmCQ"},
    ],
}

U1 = {
    "update": {
        "schema": "bedrock.pin/1", "tenant_id": T, "gateway_id": G,
        "request_id": ID("brq", "P"), "expected_revision": 0, "target": P1,
        "expires_at": "2026-09-12T00:05:00.000Z",
    },
    "signatures": [
        {"key_id": KA, "signature": "tetA1QagofywSIzJFBG2TH4TSe7orgfF7D0NK2LcNdZQmXJFjSqMrrjcktmp7-m2BIFigny2VPDDiDuUOUXODw"},
        {"key_id": KB, "signature": "mkox59vMlWQ5Alpl0ultLTnsJzzJI-k4SybO5qI_AczMsW6pi9xk854mptII3nVchYz-HuGxvTzsS_zMCs62Cg"},
    ],
}

E1BODY = {
    "schema": "bedrock.audit/1", "tenant_id": T, "log_id": L, "seq": 1,
    "prev_hash": "0" * 64, "time": T0, "actor_id": O, "subject_id": C,
    "policy_pin": P1,
    "event": {"type": "CharterPublished", "value": {"pin": P1, "source": C1["source"]}},
}

E1 = {
    "body": E1BODY,
    "hash": "57e872be05ec64b518fb9e0b80a04ab2d57b2682aeede1fe331d211176878648",
    "key_id": KC,
    "signature": "_ksWNshTO9Q0cpqxvGODWDVgvmfYeRtVpjlHQ4vYzBG7arJe5DBiZZ5v9SV-1y28ZOCO8ivtpufa6dyRv-4CCw",
}

CPBODY = {
    "schema": "bedrock.checkpoint/1", "tenant_id": T, "log_id": L,
    "through_seq": 1, "head_hash": E1["hash"], "time": T0,
}

CP1 = {
    "body": CPBODY, "key_id": KC,
    "signature": "wgjAazkaOKtV_VuUad2grfqCyjR2TrRjverc8bMHVS6O1tz0SISrfks6whPotUOU8I7-Ty36TvG4JkD-Wo1_AA",
}

EV1 = {
    "schema": "bedrock.evidence/1", "root": R, "bundles": [B1], "start": None,
    "entries": [E1], "pin_updates": [], "end": CP1, "inputs": [],
}

Q1 = {
    "request_id": ID("brq", "Q"), "pin": P1, "scope": "task-a",
    "tool": "record.get", "resource": "records/a", "args": {}, "deadline": T30,
}

PRINCIPAL = {"principal_id": A, "scopes": ["task-a"]}
ALLOW = {"verdict": "ALLOW", "reason": "ALLOW_SCOPE", "rule_ids": [RA]}
IH1 = "ce3a8db86c3349ba627a76c4113895747cedc808234e00ab2046b53f2a676df8"
OH1 = "16cfa6ba3d308e6c52a96d7d50018be09d175a518b74d5bcc6e39281ef75fa9b"

HB1 = {
    "request_id": ID("brq", "H"), "instance_id": I, "counter": 1,
    "observed_pin": P1, "manifest_hash": MH,
}

DR1 = {
    "request_id": ID("brq", "D"), "dispute_id": ID("bds", "A"), "pin": P1,
    "audit_seq": 4, "category": "SCOPE_MATCH",
    "statement": "Please review whether records/a belongs in task-a.",
    "evidence_hashes": [],
}

F = {
    "eval": {
        "charter": C1, "manifest": M1, "active_pin": P1, "request": Q1,
        "principal": PRINCIPAL, "now": T0,
    },
    "head": B1,
    "deployment": {
        "gateway_id": G, "revision": 1, "state": "ACTIVE", "pin": P1,
        "installed_manifest_hash": MH, "in_flight": 0,
    },
    "audit_head": 3,
    "heartbeat": HB1,
    "heartbeat_received_at": T0,
}

STALE_FLEET = {
    "as_of": T180, "desired_pin": P1, "status": "MISSING",
    "instances": [{
        "instance_id": I, "counter": 1, "received_at": T0, "expires_at": T180,
        "observed_pin": P1, "manifest_hash": MH, "state": "MISSING",
    }],
}

BEARER_AGENT = "fixture-agent-credential-9f4e2b7c1a"
BEARER_OPERATOR = "fixture-operator-credential-3d8f1c6e"
BEARER_INSTANCE = "fixture-instance-credential-77aa05d2"
BEARER_READER = "fixture-reader-credential-51bb990c"
BEARER_PUBLISHER = "fixture-publisher-credential-0fe1a2b3"


def fixture_auth_records() -> list:
    return [
        {"token_hash": sha256_hex(BEARER_AGENT.encode()), "tenant_id": T,
         "principal_id": A, "role": "agent", "scopes": ["task-a"],
         "instance_id": I, "expires_at": "2026-09-13T00:00:00.000Z"},
        {"token_hash": sha256_hex(BEARER_OPERATOR.encode()), "tenant_id": T,
         "principal_id": O, "role": "operator", "scopes": [],
         "instance_id": None, "expires_at": "2026-09-13T00:00:00.000Z"},
        {"token_hash": sha256_hex(BEARER_INSTANCE.encode()), "tenant_id": T,
         "principal_id": ID("bpr", "I"), "role": "instance", "scopes": [],
         "instance_id": I, "expires_at": "2026-09-13T00:00:00.000Z"},
        {"token_hash": sha256_hex(BEARER_READER.encode()), "tenant_id": T,
         "principal_id": ID("bpr", "R"), "role": "reader", "scopes": [],
         "instance_id": None, "expires_at": "2026-09-13T00:00:00.000Z"},
        {"token_hash": sha256_hex(BEARER_PUBLISHER.encode()), "tenant_id": T,
         "principal_id": ID("bpr", "P"), "role": "publisher", "scopes": [],
         "instance_id": None, "expires_at": "2026-09-13T00:00:00.000Z"},
    ]


def hex_seed_sign(n: int, kind: str, body) -> str:
    return b64url_encode(ed25519_sign(hex_decode(SEEDS[n]), S(kind, body)))


def seed_public_key(n: int) -> str:
    return ed25519_public_key(hex_decode(SEEDS[n])).hex()


FIXTURE_ADAPTER_BUILD_HASH = M1["adapter_build_hash"]

FIXTURES = {
    "C1": C1, "C2": C2, "B1": B1, "B2": B2, "R": R, "M1": M1,
    "P1": P1, "P2": P2, "U1": U1, "E1": E1, "E1BODY": E1BODY,
    "CP1": CP1, "CPBODY": CPBODY, "EV1": EV1, "Q1": Q1, "F": F,
    "PRINCIPAL": PRINCIPAL, "ALLOW": ALLOW, "HB1": HB1, "DR1": DR1,
    "staleFleet": STALE_FLEET,
}
