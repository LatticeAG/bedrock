"""bedrock CLI (spec §8.1) — `python -m bedrock`. Mirrors src/cli.ts:
same 23 subcommands, canonical JSON + LF on stdout, diagnostics on stderr,
same exit codes."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from .errors import BedrockError, exit_code_for, NotImplementedSurface
from .canon import canonical_string, parse_json_bytes
from .yaml_strict import parse_yaml
from .crypto import D, S, hex_decode, ed25519_sign, b64url_encode
from .schema import (
    v_bundle, v_charter, v_manifest, v_call_request, v_dispute_request,
    v_heartbeat, v_signed_pin_update, v_detached, v_pin_update, v_root_file,
    v_evidence,
)
from .compiler import compile_bundle
from .bundle import verify_bundle, canonical_equal
from .evidence import verify_evidence
from .diff import semantic_diff
from .client import BedrockClient, ApiError
from .config import (
    load_config, load_auth_records, load_response_keys, load_audit_seed,
    client_credential, resolve_env_ref,
)
from .timeutil import parse_time

VERSION = "0.1.0"

REPEATABLE = {"signature", "predecessor"}
BOOL_FLAGS = {"json", "replace", "local", "replay", "help", "version"}


class _Args:
    def __init__(self, argv):
        self.positional: list[str] = []
        self.flags: dict = {}
        self.repeated: dict = {}
        i = 0
        while i < len(argv):
            a = argv[i]
            if a.startswith("--"):
                eq = a.find("=")
                if eq != -1:
                    name, val = a[2:eq], a[eq + 1:]
                else:
                    name = a[2:]
                    if name not in BOOL_FLAGS and i + 1 < len(argv) and not argv[i + 1].startswith("--"):
                        i += 1
                        val = argv[i]
                    else:
                        val = True
                if name in REPEATABLE:
                    self.repeated.setdefault(name, []).append(val)
                else:
                    self.flags[name] = val
            else:
                self.positional.append(a)
            i += 1

    def flag(self, name):
        v = self.flags.get(name)
        return None if v is True else v

    def flag_bool(self, name):
        return name in self.flags

    def flag_int(self, name, default=None):
        v = self.flags.get(name)
        if v is None:
            if default is not None:
                return default
            raise BedrockError("SCHEMA", f"missing required --{name}")
        if v is True or not re.match(r"^(0|[1-9][0-9]*)$", str(v)):
            raise BedrockError("SCHEMA", f"--{name} must be a canonical unsigned integer")
        n = int(v)
        if n > 9007199254740991:
            raise BedrockError("SCHEMA", f"--{name} out of range")
        return n

    def need(self, name):
        v = self.flag(name)
        if v is None:
            raise BedrockError("SCHEMA", f"missing required --{name}")
        return v

    def pos(self, i, name):
        if i >= len(self.positional):
            raise BedrockError("SCHEMA", f"missing argument {name}")
        return self.positional[i]


def _out(v):
    sys.stdout.write(canonical_string(v) + "\n")


def _err(s):
    sys.stderr.write(s + "\n")


def _read_json_file(path: str):
    try:
        return parse_json_bytes(Path(path).read_bytes())
    except BedrockError:
        raise
    except OSError:
        raise BedrockError("PARSE", f"cannot read {path}")


def _read_charter_file(path: str):
    try:
        raw = Path(path).read_text("utf-8")
    except OSError:
        raise BedrockError("PARSE", f"cannot read {path}")
    if raw.lstrip().startswith("{"):
        return v_charter(parse_json_bytes(raw.encode("utf-8")))
    return v_charter(parse_yaml(raw))


def _write_out(path: str, data: bytes, replace: bool):
    if Path(path).exists() and not replace:
        raise BedrockError("SCHEMA", f"{path} exists; pass --replace")
    Path(path).write_bytes(data)


def _make_client(args: _Args):
    cfg_path = args.flag("config") or "./bedrock.yaml"
    loaded = load_config(cfg_path)
    credential = client_credential(loaded.config)
    timeout_ms = args.flag_int("timeout-ms", 10000)
    if not 1 <= timeout_ms <= 60000:
        raise BedrockError("SCHEMA", "--timeout-ms outside [1,60000]")
    client = BedrockClient(loaded.config["endpoint"], credential, timeout_ms)
    return client, loaded


def _load_key_from_ref(ref: str) -> bytes:
    hexs = resolve_env_ref(ref).strip()
    if not re.match(r"^[0-9a-f]{64}$", hexs):
        raise BedrockError("SCHEMA", "key material must be 64 lowercase hex")
    return bytes.fromhex(hexs)


def _warnings_for(c: dict) -> list:
    import time as _t

    w = []
    if not c["scope_rules"]:
        w.append("NO_ALLOW_RULES")
    if c["next_authority"]["threshold"] == 1:
        w.append("SINGLE_SIGNER")
    if parse_time(c["not_after"]) - int(_t.time() * 1000) <= 24 * 3600 * 1000:
        w.append("EXPIRY_WITHIN_24H")
    return sorted(w)


# ---------------------------------------------------------------------------


def cmd_charter_lint(args: _Args) -> int:
    charter = _read_charter_file(args.pos(0, "FILE"))
    manifest = v_manifest(_read_json_file(args.need("manifest")))
    root = v_root_file(_read_json_file(args.need("root")))
    c = compile_bundle(charter, manifest)
    if (
        charter["tenant_id"] != root["tenant_id"]
        or charter["charter_id"] != root["charter_id"]
        or manifest["gateway_id"] != root["gateway_id"]
    ):
        raise BedrockError("SCHEMA", "charter/manifest lineage does not match root")
    pred = args.flag("predecessor")
    if pred is not None:
        p = v_bundle(_read_json_file(pred))
        if charter["previous_hash"] != D("charter", p["charter"]):
            raise BedrockError("HASH_MISMATCH", "previous_hash does not match predecessor")
        if charter["version"] != p["charter"]["version"] + 1:
            raise BedrockError("VERSION_CONFLICT", "version must be predecessor + 1")
    _out({
        "valid": True, "charter_hash": c["charter_hash"],
        "manifest_hash": c["manifest_hash"], "warnings": _warnings_for(charter),
    })
    return 0


def cmd_charter_canonicalize(args: _Args) -> int:
    charter = _read_charter_file(args.pos(0, "FILE"))
    data = canonical_string(charter).encode("utf-8")
    out_path = args.need("out")
    _write_out(out_path, data, args.flag_bool("replace"))
    _out({"charter_hash": D("charter", charter), "bytes": len(data), "out": out_path})
    return 0


def cmd_charter_diff(args: _Args) -> int:
    old_c = _read_charter_file(args.pos(0, "OLD"))
    new_c = _read_charter_file(args.pos(1, "NEW"))
    manifest = v_manifest(_read_json_file(args.need("manifest")))
    compile_bundle(old_c, manifest)
    compile_bundle(new_c, manifest)
    changes = semantic_diff(old_c, new_c)
    _out({
        "old_hash": D("charter", old_c), "new_hash": D("charter", new_c),
        "changes": changes,
        "authority_changed": not canonical_equal(old_c["next_authority"], new_c["next_authority"]),
    })
    return 0


def cmd_charter_sign(args: _Args) -> int:
    charter = _read_charter_file(args.pos(0, "FILE"))
    manifest = v_manifest(_read_json_file(args.need("manifest")))
    compile_bundle(charter, manifest)
    key_id = args.need("key-id")
    seed = _load_key_from_ref(args.need("key-ref"))
    sig = ed25519_sign(seed, S("charter", charter))
    detached = {"key_id": key_id, "signature": b64url_encode(sig)}
    out_path = args.need("out")
    _write_out(out_path, canonical_string(detached).encode("utf-8"), args.flag_bool("replace"))
    _out({"charter_hash": D("charter", charter), "key_id": key_id, "out": out_path})
    return 0


def cmd_charter_bundle(args: _Args) -> int:
    charter = _read_charter_file(args.pos(0, "FILE"))
    manifest = v_manifest(_read_json_file(args.need("manifest")))
    root = v_root_file(_read_json_file(args.need("root")))
    sig_files = args.repeated.get("signature", [])
    if not sig_files:
        raise BedrockError("SCHEMA", "at least one --signature is required")
    sigs = [v_detached(_read_json_file(f)) for f in sig_files]
    bundle = {"charter": charter, "manifest": manifest, "signatures": sigs}
    preds = [v_bundle(_read_json_file(f)) for f in args.repeated.get("predecessor", [])]
    verify_bundle(bundle, root, preds)
    out_path = args.need("out")
    _write_out(out_path, canonical_string(bundle).encode("utf-8"), args.flag_bool("replace"))
    _out({"charter_hash": D("charter", charter), "signatures": len(sigs), "out": out_path})
    return 0


def cmd_charter_verify(args: _Args) -> int:
    bundle = v_bundle(_read_json_file(args.pos(0, "BUNDLE")))
    root = v_root_file(_read_json_file(args.need("root")))
    preds = [v_bundle(_read_json_file(f)) for f in args.repeated.get("predecessor", [])]
    r = verify_bundle(bundle, root, preds)
    _out({"valid": True, "pin": r["pin"], "signatures": r["signatures"], "required": r["required"]})
    return 0


def cmd_charter_publish(args: _Args) -> int:
    bundle = v_bundle(_read_json_file(args.pos(0, "BUNDLE")))
    request_id = args.need("request-id")
    client, _ = _make_client(args)
    _out(client.charter_publish(request_id, bundle))
    return 0


def cmd_charter_fetch(args: _Args) -> int:
    v_raw = args.pos(0, "VERSION")
    if not re.match(r"^[1-9][0-9]*$", v_raw):
        raise BedrockError("SCHEMA", "VERSION must be canonical positive decimal")
    client, loaded = _make_client(args)
    bundle = client.charter_version(int(v_raw))
    preds = [client.charter_version(i) for i in range(1, bundle["charter"]["version"])]
    r = verify_bundle(bundle, loaded.root, preds)
    out_path = args.need("out")
    _write_out(out_path, canonical_string(bundle).encode("utf-8"), args.flag_bool("replace"))
    _out({"pin": r["pin"], "out": out_path})
    return 0


def cmd_pin_sign(args: _Args) -> int:
    bundle = v_bundle(_read_json_file(args.need("bundle")))
    cfg = load_config(args.flag("config") or "./bedrock.yaml").config
    target = {
        "charter_id": bundle["charter"]["charter_id"],
        "version": bundle["charter"]["version"],
        "charter_hash": D("charter", bundle["charter"]),
        "manifest_hash": D("manifest", bundle["manifest"]),
        "engine": bundle["charter"]["engine"],
    }
    update = {
        "schema": "bedrock.pin/1", "tenant_id": cfg["tenant_id"],
        "gateway_id": cfg["gateway_id"], "request_id": args.need("request-id"),
        "expected_revision": args.flag_int("expected-revision"),
        "target": target, "expires_at": args.need("expires-at"),
    }
    v_pin_update(update)
    key_id = args.need("key-id")
    seed = _load_key_from_ref(args.need("key-ref"))
    sig = {"key_id": key_id, "signature": b64url_encode(ed25519_sign(seed, S("pin", update)))}
    out_path = args.need("out")
    _write_out(
        out_path, canonical_string({"update": update, "signature": sig}).encode("utf-8"),
        args.flag_bool("replace"),
    )
    _out({"charter_hash": target["charter_hash"], "key_id": key_id, "out": out_path})
    return 0


def cmd_pin_activate(args: _Args) -> int:
    u = v_signed_pin_update(_read_json_file(args.pos(0, "UPDATE")))
    client, _ = _make_client(args)
    _out(client.pin(u))
    return 0


def cmd_gateway_pause(args: _Args) -> int:
    client, _ = _make_client(args)
    _out(client.pause({
        "request_id": args.need("request-id"),
        "expected_revision": args.flag_int("expected-revision"),
        "reason": args.need("reason"),
    }))
    return 0


def cmd_gateway_status(args: _Args) -> int:
    client, _ = _make_client(args)
    deployment = client.deployment()
    try:
        readiness = client.readyz()
    except ApiError as e:
        readiness = {"ready": False, "error": e.code}
    _out({"deployment": deployment, "readiness": readiness})
    return 0


def cmd_gateway_check(args: _Args) -> int:
    req = v_call_request(_read_json_file(args.pos(0, "REQUEST")))
    client, _ = _make_client(args)
    r = client.check(req)
    _out(r)
    return 0 if r["decision"]["verdict"] == "ALLOW" else 3


def cmd_gateway_call(args: _Args) -> int:
    req = v_call_request(_read_json_file(args.pos(0, "REQUEST")))
    client, _ = _make_client(args)
    _status, result = client.call(req)
    _out(result)
    return {"SUCCEEDED": 0, "DENIED": 3, "DISPATCHED": 8, "INDETERMINATE": 8, "FAILED": 9}[result["state"]]


def cmd_gateway_result(args: _Args) -> int:
    client, _ = _make_client(args)
    _status, result = client.call_result(args.pos(0, "ID"))
    _out(result)
    return {"SUCCEEDED": 0, "DENIED": 3, "DISPATCHED": 8, "INDETERMINATE": 8, "FAILED": 9}[result["state"]]


def cmd_dispute_record(args: _Args) -> int:
    req = v_dispute_request(_read_json_file(args.pos(0, "FILE")))
    client, _ = _make_client(args)
    _out(client.dispute(req))
    return 0


def cmd_dispute_list(args: _Args) -> int:
    client, _ = _make_client(args)
    _out(client.disputes(args.flag_int("after-seq", 0), args.flag_int("limit", 100)))
    return 0


def cmd_fleet_status(args: _Args) -> int:
    import time as _t

    client, _ = _make_client(args)
    watch_ms = args.flag_int("watch-ms") if "watch-ms" in args.flags else None
    if watch_ms is not None and not 1000 <= watch_ms <= 60000:
        raise BedrockError("SCHEMA", "--watch-ms outside [1000,60000]")
    if watch_ms is None:
        fleet = client.fleet()
        _out(fleet)
        return 0 if fleet["status"] == "HEALTHY" else 3
    while True:
        sys.stdout.write(canonical_string(client.fleet()) + "\n")
        sys.stdout.flush()
        _t.sleep(watch_ms / 1000)


def cmd_fleet_heartbeat(args: _Args) -> int:
    hb = v_heartbeat(_read_json_file(args.pos(0, "FILE")))
    client, _ = _make_client(args)
    _out(client.heartbeat(hb))
    return 0


def cmd_audit_export(args: _Args) -> int:
    through_seq = args.flag_int("through-seq")
    client, loaded = _make_client(args)
    entries: list = []
    pin_updates: list = []
    after = 0
    while True:
        page = client.audit(after, through_seq, 100)
        entries.extend(page["entries"])
        pin_updates.extend(page["pin_updates"])
        if page["next_after"] is None:
            break
        after = page["next_after"]
    end = client.checkpoint(through_seq)
    versions = client.charter_versions(0, 100)
    bundles = [client.charter_version(v["version"]) for v in versions["versions"]]
    start = None
    from_cp = args.flag("from-checkpoint")
    if from_cp is not None:
        start = _read_json_file(from_cp)
    inputs_file = args.flag("inputs")
    inputs = _read_json_file(inputs_file) if inputs_file is not None else []
    evidence = {
        "schema": "bedrock.evidence/1", "root": loaded.root, "bundles": bundles,
        "start": start, "entries": entries, "pin_updates": pin_updates,
        "end": end, "inputs": inputs,
    }
    out_path = args.need("out")
    _write_out(out_path, canonical_string(evidence).encode("utf-8"), args.flag_bool("replace"))
    _out({"through_seq": through_seq, "entries": len(entries), "out": out_path})
    return 0


def cmd_audit_verify(args: _Args) -> int:
    evidence = v_evidence(_read_json_file(args.pos(0, "FILE")))
    root = v_root_file(_read_json_file(args.need("root")))
    trusted_cp = args.flag("trusted-checkpoint")
    trusted = _read_json_file(trusted_cp) if trusted_cp is not None else None
    v = verify_evidence(evidence, root, trusted, args.flag_bool("replay"))
    _out(v)
    if v["integrity"] == "INVALID" or v["replay"] == "MISMATCH":
        return 4
    if v["integrity"] == "INCOMPLETE" or v["replay"] in ("INPUTS_MISSING", "CONTEXT_MISSING"):
        return 8
    return 0


def cmd_serve(args: _Args) -> int:
    local = args.flag_bool("local")
    load_config(args.flag("config") or "./bedrock.yaml")  # validates config
    if not local:
        _out({"deployment_required": True})
        return 0
    raise NotImplementedSurface(
        "serve --local runs the gateway emulator, which ships in the TypeScript "
        "package (`bedrock serve --local`). The Python distribution carries the "
        "offline toolchain and HTTP SDK only. See "
        "https://github.com/LatticeAG/bedrock"
    )


def cmd_config_validate(args: _Args) -> int:
    loaded = load_config(
        args.flag("config") or (args.positional[0] if args.positional else "./bedrock.yaml")
    )
    manifest = v_manifest(
        _read_json_file(str(Path(loaded.dir) / loaded.config["manifest_file"]))
    )
    for ref in (
        loaded.config["client_credential_ref"], loaded.config["auth_records_ref"],
        loaded.config["audit_seed_ref"], loaded.config["response_keys_ref"],
    ):
        resolve_env_ref(ref)
    _out({
        "valid": True, "manifest_hash": D("manifest", manifest),
        "instance_count": len(loaded.config["instance_inventory"]),
    })
    return 0


# ---------------------------------------------------------------------------

COMMANDS = {
    "charter lint": cmd_charter_lint,
    "charter canonicalize": cmd_charter_canonicalize,
    "charter diff": cmd_charter_diff,
    "charter sign": cmd_charter_sign,
    "charter bundle": cmd_charter_bundle,
    "charter verify": cmd_charter_verify,
    "charter publish": cmd_charter_publish,
    "charter fetch": cmd_charter_fetch,
    "pin sign": cmd_pin_sign,
    "pin activate": cmd_pin_activate,
    "gateway pause": cmd_gateway_pause,
    "gateway status": cmd_gateway_status,
    "gateway check": cmd_gateway_check,
    "gateway call": cmd_gateway_call,
    "gateway result": cmd_gateway_result,
    "dispute record": cmd_dispute_record,
    "dispute list": cmd_dispute_list,
    "fleet status": cmd_fleet_status,
    "fleet heartbeat": cmd_fleet_heartbeat,
    "audit export": cmd_audit_export,
    "audit verify": cmd_audit_verify,
    "serve": cmd_serve,
    "config validate": cmd_config_validate,
}

HELP = f"""bedrock {VERSION} — versioned signed charters, exact pins, enforced gateway.

Usage: bedrock <command> [flags]

Commands:
  charter lint FILE --manifest M --root R [--predecessor B]
  charter canonicalize FILE --out F [--replace]
  charter diff OLD NEW --manifest M
  charter sign FILE --manifest M --key-id ID --key-ref env:VAR --out F [--replace]
  charter bundle FILE --manifest M --signature S... --root R --out F [--predecessor B...] [--replace]
  charter verify BUNDLE --root R [--predecessor B...]
  charter publish BUNDLE --request-id ID
  charter fetch VERSION --out F [--replace]
  pin sign --bundle B --expected-revision N --request-id ID --expires-at T --key-id ID --key-ref env:VAR --out F
  pin activate UPDATE
  gateway pause --expected-revision N --request-id ID --reason TEXT
  gateway status
  gateway check REQUEST.json
  gateway call REQUEST.json
  gateway result REQUEST_ID
  dispute record FILE.json
  dispute list [--after-seq N] [--limit N]
  fleet status [--watch-ms N]
  fleet heartbeat FILE.json
  audit export --through-seq N --out F [--from-checkpoint F --inputs F --replace]
  audit verify FILE --root R [--trusted-checkpoint F --replay]
  serve --local
  config validate

Global flags: --config PATH  --json  --timeout-ms N  --version  --help
"""


def main(argv) -> int:
    args = _Args(argv)
    if args.flag_bool("version"):
        _out({"version": VERSION})
        return 0
    if args.flag_bool("help") or not args.positional:
        sys.stdout.write(HELP)
        return 2 if not args.positional and not args.flag_bool("help") else 0
    key = f"{args.positional[0]} {args.positional[1] if len(args.positional) > 1 else ''}".strip()
    cmd = COMMANDS.get(key) or COMMANDS.get(args.positional[0])
    if cmd is None:
        _err(f"unknown command: {key}")
        return 2
    sub = _Args.__new__(_Args)
    sub.positional = args.positional[2 if " " in key else 1:]
    sub.flags = args.flags
    sub.repeated = args.repeated
    try:
        return cmd(sub)
    except ApiError as e:
        _out({"error": {"code": e.code, "retryable": e.retryable, "audit_seq": e.audit_seq}})
        return exit_code_for(e.code)
    except BedrockError as e:
        _out({"error": {"code": e.code, "retryable": e.retryable, "audit_seq": e.audit_seq}})
        return exit_code_for(e.code)
    except NotImplementedSurface as e:
        _err(str(e))
        return 2


def _entrypoint():
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    _entrypoint()
