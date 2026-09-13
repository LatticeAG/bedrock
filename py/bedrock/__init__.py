"""latticeagi-bedrock — MIT core: versioned signed charters, exact pins,
deterministic gateway evaluation, offline bundle/evidence verification.

The gateway runtime (Durable Object + SQLite) ships in the TypeScript package
`@latticeagi/bedrock`; this distribution carries the identical pure core,
the HTTP client SDK, and the `python -m bedrock` CLI.
"""
from .errors import BedrockError, NotImplementedSurface, api_error, exit_code_for
from .canon import (
    J, canonical_string, canonical_key_order, parse_json, parse_json_bytes,
    assert_canonical_json,
)
from .yaml_strict import parse_yaml, parse_yaml_bytes
from .crypto import (
    D, S, sha256, sha256_hex, b64url_encode, b64url_decode, hex_decode,
    is_hash, ed25519_public_key, ed25519_sign, ed25519_verify,
    sign_object, verify_object, is_acceptable_point, is_acceptable_public_key,
    aes_gcm_encrypt, aes_gcm_decrypt, HASH_KINDS,
)
from .compiler import compile_bundle, check_lineage, pin_of, manifest_digest_or_throw
from .evaluator import evaluate, check_args
from .bundle import (
    verify_bundle, verify_pin_update_signatures, check_signatures, canonical_equal,
)
from .evidence import verify_evidence
from .diff import semantic_diff
from .client import BedrockClient, ApiError
from .ids import new_id, is_bedrock_id, fixed_id, ID_ALPHABET, PREFIXES
from .timeutil import is_time, parse_time, format_time

__version__ = "0.1.0"
