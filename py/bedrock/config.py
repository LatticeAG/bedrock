"""Configuration loading (spec §9.1–9.2). Mirrors src/config.ts."""
from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import urlparse

from .errors import BedrockError
from .yaml_strict import parse_yaml
from .canon import parse_json_bytes
from .crypto import hex_decode
from .schema import v_config, v_root_file, v_auth_record
from .fixtures import PUB

ENV_REF = re.compile(r"^env:[A-Z][A-Z0-9_]{0,63}$")


def is_env_ref(s: str) -> bool:
    return bool(ENV_REF.match(s))


def resolve_env_ref(ref: str) -> str:
    if not is_env_ref(ref):
        raise BedrockError("SCHEMA", f"bad secret reference {ref}")
    v = os.environ.get(ref[4:])
    if v is None:
        raise BedrockError("SCHEMA", f"environment variable {ref[4:]} not set")
    return v


class LoadedConfig:
    def __init__(self, config: dict, dir: str, root: dict):
        self.config = config
        self.dir = dir
        self.root = root


def load_config(path: str) -> LoadedConfig:
    try:
        raw = Path(path).read_text("utf-8")
    except OSError:
        raise BedrockError("SCHEMA", f"config file not found: {path}")
    cfg = v_config(parse_yaml(raw))
    d = str(Path(path).resolve().parent)
    root = load_root(str(Path(d) / cfg["root_file"]))
    if root["tenant_id"] != cfg["tenant_id"] or root["gateway_id"] != cfg["gateway_id"]:
        raise BedrockError("SCHEMA", "root file tenant/gateway mismatch")
    if cfg["storage_soft_limit_bytes"] > 8589934592:
        raise BedrockError("SCHEMA", "storage_soft_limit_bytes exceeds the 8 GiB v1 bound")
    if not 1 <= cfg["max_in_flight"] <= 32:
        raise BedrockError("SCHEMA", "max_in_flight outside [1,32]")
    inv = cfg["instance_inventory"]
    if len(set(inv)) != len(inv) or not 1 <= len(inv) <= 32:
        raise BedrockError("SCHEMA", "instance_inventory must be 1-32 distinct ids")
    if cfg["instance_id"] not in inv:
        raise BedrockError("SCHEMA", "instance_id not in instance_inventory")
    if cfg["environment"] == "production":
        _production_rejections(cfg, root)
    return LoadedConfig(cfg, d, root)


def _production_rejections(cfg: dict, root: dict):
    for k in [*root["bootstrap"]["keys"], *root["audit_keys"]]:
        if k["public_key"] in PUB:
            raise BedrockError("SCHEMA", "production rejects published fixture keys")
    if not cfg["endpoint"].startswith("https://"):
        raise BedrockError("SCHEMA", "production endpoint must be HTTPS, non-loopback")
    u = urlparse(cfg["endpoint"])
    if u.username or u.password or u.path not in ("", "/") or u.query or u.fragment:
        raise BedrockError(
            "SCHEMA", "endpoint must be an origin without credentials/path/query/fragment"
        )
    if u.hostname in ("localhost", "127.0.0.1", "::1"):
        raise BedrockError("SCHEMA", "production endpoint must not be loopback")
    for ref in (
        cfg["client_credential_ref"], cfg["auth_records_ref"],
        cfg["audit_seed_ref"], cfg["response_keys_ref"],
    ):
        if not is_env_ref(ref):
            raise BedrockError("SCHEMA", "production requires env: secret handles")


def load_root(path: str) -> dict:
    root = v_root_file(parse_json_bytes(Path(path).read_bytes()))
    boot = {k["public_key"] for k in root["bootstrap"]["keys"]}
    per_id: dict = {}
    for k in root["audit_keys"]:
        if k["public_key"] in boot:
            raise BedrockError("SCHEMA", "audit key may not be a bootstrap key")
        for r in per_id.get(k["key_id"], []):
            b1 = k["through_seq"] if k["through_seq"] is not None else 2**53 - 1
            b2 = r[1] if r[1] is not None else 2**53 - 1
            if k["from_seq"] <= b2 and r[0] <= b1:
                raise BedrockError("SCHEMA", f"audit key {k['key_id']} ranges overlap")
        per_id.setdefault(k["key_id"], []).append((k["from_seq"], k["through_seq"]))
    return root


def load_auth_records(cfg: dict) -> list:
    raw = resolve_env_ref(cfg["auth_records_ref"])
    arr = parse_json_bytes(raw.encode("utf-8"))
    if not isinstance(arr, list):
        raise BedrockError("SCHEMA", "auth records must be an array")
    records = [v_auth_record(r) for r in arr]
    seen = set()
    for r in records:
        if r["token_hash"] in seen:
            raise BedrockError("SCHEMA", "duplicate credential hash")
        seen.add(r["token_hash"])
        if r["tenant_id"] != cfg["tenant_id"]:
            raise BedrockError("SCHEMA", "auth record tenant mismatch")
        bound = r["role"] in ("agent", "instance")
        if bound and (r["instance_id"] is None or r["instance_id"] not in cfg["instance_inventory"]):
            raise BedrockError(
                "SCHEMA", "agent/instance record requires a configured instance_id"
            )
        if not bound and r["instance_id"] is not None:
            raise BedrockError(
                "SCHEMA", "non-agent/instance record requires instance_id null"
            )
        if r["principal_id"] == cfg["system_principal_id"]:
            raise BedrockError(
                "SCHEMA", "system_principal_id must not appear in auth records"
            )
        if r["scopes"] != sorted(set(r["scopes"])) or len(set(r["scopes"])) != len(r["scopes"]):
            raise BedrockError("SCHEMA", "principal scopes must be sorted unique")
        if r["role"] == "instance" and r["scopes"]:
            raise BedrockError("SCHEMA", "instance records have no agent tool scope")
    return records


def load_response_keys(cfg: dict) -> dict:
    raw = resolve_env_ref(cfg["response_keys_ref"])
    rk = parse_json_bytes(raw.encode("utf-8"))
    if not isinstance(rk, dict):
        raise BedrockError("SCHEMA", "bad response keys object")
    if not isinstance(rk.get("active_key_id"), str) or not isinstance(rk.get("keys"), list):
        raise BedrockError("SCHEMA", "bad response keys object")
    ids = set()
    for k in rk["keys"]:
        if not isinstance(k, dict) or not isinstance(k.get("key_id"), str) or not isinstance(k.get("key_base64url"), str):
            raise BedrockError("SCHEMA", "bad response key entry")
        if k["key_id"] in ids:
            raise BedrockError("SCHEMA", "duplicate response key id")
        ids.add(k["key_id"])
        try:
            b = hex_decode_b64(k["key_base64url"])
        except BedrockError:
            raise BedrockError("SCHEMA", "response key must be canonical base64url of 32 bytes")
        if len(b) != 32:
            raise BedrockError("SCHEMA", "response key must be canonical base64url of 32 bytes")
    if not 1 <= len(rk["keys"]) <= 8 or rk["active_key_id"] not in ids:
        raise BedrockError("SCHEMA", "response keys must be 1-8 with active id present")
    return rk


def hex_decode_b64(s: str) -> bytes:
    from .crypto import b64url_decode

    return b64url_decode(s)


def load_audit_seed(cfg: dict, root: dict) -> bytes:
    hexs = resolve_env_ref(cfg["audit_seed_ref"]).strip()
    if not re.match(r"^[0-9a-f]{64}$", hexs):
        raise BedrockError("SCHEMA", "audit seed must be 64 lowercase hex")
    if not any(k["key_id"] == cfg["audit_key_id"] for k in root["audit_keys"]):
        raise BedrockError("SCHEMA", "audit_key_id absent from root audit_keys")
    return bytes.fromhex(hexs)


def client_credential(cfg: dict) -> str:
    return resolve_env_ref(cfg["client_credential_ref"])
