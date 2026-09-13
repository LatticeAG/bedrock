"""Hash and signature primitives (spec §3.3). Mirrors src/crypto.ts.

D(kind,x) = lowercase_hex(SHA256(UTF8("LAGI-BEDROCK/" + kind + "/1\\n") || J(x)))
S(kind,x) = UTF8("LAGI-BEDROCK/sign/" + kind + "/1\\n" + D(kind,x))

Ed25519 is implemented here in pure Python so that canonicality checks —
noncanonical encodings, S >= L, small-order public keys / R points — are
identical to the TypeScript core. AES-256-GCM uses `cryptography`.
"""
from __future__ import annotations

import base64
import hashlib
import re

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import BedrockError
from .canon import J

HASH_KINDS = ("manifest", "charter", "pin", "input", "audit", "checkpoint")


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha512(b: bytes) -> bytes:
    return hashlib.sha512(b).digest()


def D(kind: str, x) -> str:
    if kind not in HASH_KINDS:
        raise BedrockError("SCHEMA", f"unknown hash kind {kind}")
    return sha256_hex(f"LAGI-BEDROCK/{kind}/1\n".encode("utf-8") + J(x))


def S(kind: str, x) -> bytes:
    return f"LAGI-BEDROCK/sign/{kind}/1\n{D(kind, x)}".encode("utf-8")


# ---------------------------------------------------------------------------
# base64url (canonical, unpadded)
# ---------------------------------------------------------------------------

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def b64url_decode(s: str) -> bytes:
    if not _B64URL_RE.match(s):
        raise BedrockError("PARSE", "invalid base64url")
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if b64url_encode(b) != s:
        raise BedrockError("PARSE", "noncanonical base64url")
    return b


HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def is_hash(s) -> bool:
    return isinstance(s, str) and bool(HEX64_RE.match(s))


def hex_decode(s: str) -> bytes:
    if not re.match(r"^[0-9a-f]+$", s) or len(s) % 2 != 0:
        raise BedrockError("PARSE", "invalid lowercase hex")
    return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# Ed25519 — strict canonical verification + RFC 8032 signing, pure Python.
# ---------------------------------------------------------------------------

ED_P = (1 << 255) - 19
ED_L = (1 << 252) + 27742317777372353535851937790883648493
ED_D = 37095705934669439343138083508754565189542113879843219016388785533085940283555
ED_SQRT_M1 = 19681161376707505956807079304988542015446066515923890162744021073123829784752
IDENTITY = (0, 1)


def _fe(x: int) -> int:
    return x % ED_P


def _ed_add(P, Q):
    x1, y1 = P
    x2, y2 = Q
    dx1x2y1y2 = ED_D * x1 % ED_P * x2 % ED_P * y1 % ED_P * y2 % ED_P
    x_num = (x1 * y2 + y1 * x2) % ED_P
    y_num = (y1 * y2 + x1 * x2) % ED_P
    x_den = pow((1 + dx1x2y1y2) % ED_P, ED_P - 2, ED_P)
    y_den = pow((1 - dx1x2y1y2) % ED_P, ED_P - 2, ED_P)
    return (x_num * x_den % ED_P, y_num * y_den % ED_P)


def _ed_mul(s: int, P) -> tuple:
    Q = IDENTITY
    while s > 0:
        if s & 1:
            Q = _ed_add(Q, P)
        P = _ed_add(P, P)
        s >>= 1
    return Q


def decode_point(enc: bytes):
    """Decode a canonical point encoding; None if noncanonical/off-curve."""
    if len(enc) != 32:
        return None
    y = int.from_bytes(enc, "little")
    x_sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= ED_P:
        return None
    yy = y * y % ED_P
    num = (yy - 1) % ED_P
    den_inv = pow((ED_D * yy + 1) % ED_P, ED_P - 2, ED_P)
    u = num * den_inv % ED_P
    x = pow(u, (ED_P + 3) >> 3, ED_P)
    if x * x % ED_P != u:
        x = x * ED_SQRT_M1 % ED_P
        if x * x % ED_P != u:
            return None
    if (x & 1) != x_sign:
        x = (ED_P - x) % ED_P
    if x == 0 and x_sign == 1:
        return None
    return (x, y)


def is_small_order(P) -> bool:
    Q = _ed_mul(8, P)
    return Q == IDENTITY


def is_acceptable_point(enc: bytes) -> bool:
    p = decode_point(enc)
    return p is not None and not is_small_order(p)


def is_acceptable_public_key(enc: bytes) -> bool:
    return is_acceptable_point(enc)


def _encode_point(P) -> bytes:
    x, y = P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _hint(b: bytes) -> int:
    return int.from_bytes(sha512(b), "little")


def _base_point() -> tuple:
    # B = (x, 4/5)
    y = 4 * pow(5, ED_P - 2, ED_P) % ED_P
    yy = y * y % ED_P
    u = (yy - 1) * pow((ED_D * yy + 1) % ED_P, ED_P - 2, ED_P) % ED_P
    x = pow(u, (ED_P + 3) >> 3, ED_P)
    if x * x % ED_P != u:
        x = x * ED_SQRT_M1 % ED_P
    if x & 1:
        x = ED_P - x
    return (x, y)


_ED_B = _base_point()


def ed25519_public_key(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise BedrockError("SCHEMA", "ed25519 seed must be 32 bytes")
    h = sha512(seed)
    a = _clamp_scalar(h[:32])
    return _encode_point(_ed_mul(a, _ED_B))


def _clamp_scalar(h: bytes) -> int:
    a = int.from_bytes(h, "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a


def ed25519_sign(seed: bytes, msg: bytes) -> bytes:
    if len(seed) != 32:
        raise BedrockError("SCHEMA", "ed25519 seed must be 32 bytes")
    h = sha512(seed)
    a = _clamp_scalar(h[:32])
    prefix = h[32:]
    A = _encode_point(_ed_mul(a, _ED_B))
    r = _hint(prefix + msg) % ED_L
    R = _encode_point(_ed_mul(r, _ED_B))
    k = _hint(R + A + msg) % ED_L
    s = (r + k * a) % ED_L
    return R + s.to_bytes(32, "little")


def ed25519_verify(pub: bytes, sig: bytes, msg: bytes) -> bool:
    """Strict verify: canonical encodings, S < L, on-curve non-small-order R/A."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    R, Sb = sig[:32], sig[32:]
    if int.from_bytes(Sb, "little") >= ED_L:
        return False
    if not is_acceptable_point(R):
        return False
    A = decode_point(pub)
    if A is None or is_small_order(A):
        return False
    Rp = decode_point(R)
    # [k]A + R == [S]B  (equivalent to [S]B == R + [k]A)
    k = _hint(R + pub + msg) % ED_L
    lhs = _ed_mul(int.from_bytes(Sb, "little"), _ED_B)
    rhs = _ed_add(Rp, _ed_mul(k, A))
    return lhs == rhs


def sign_object(kind: str, body, key_id: str, seed: bytes) -> dict:
    return {"key_id": key_id, "signature": b64url_encode(ed25519_sign(seed, S(kind, body)))}


def verify_object(kind: str, body, public_key_hex: str, signature_b64: str) -> bool:
    try:
        sig = b64url_decode(signature_b64)
        pub = hex_decode(public_key_hex)
    except BedrockError:
        return False
    if len(sig) != 64 or len(pub) != 32:
        return False
    return ed25519_verify(pub, sig, S(kind, body))


# ---------------------------------------------------------------------------
# AES-256-GCM envelope (spec §10.1)
# ---------------------------------------------------------------------------


def aes_gcm_encrypt(key: bytes, key_id: str, aad: bytes, plaintext: bytes) -> dict:
    import os

    nonce = os.urandom(12)
    ct_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "version": 1,
        "key_id": key_id,
        "nonce_base64url": b64url_encode(nonce),
        "ciphertext_base64url": b64url_encode(ct_tag),
    }


def aes_gcm_decrypt(keys: dict, aad: bytes, env: dict):
    key = keys.get(env.get("key_id"))
    if key is None:
        return None
    try:
        nonce = b64url_decode(env["nonce_base64url"])
        ct_tag = b64url_decode(env["ciphertext_base64url"])
        return AESGCM(key).decrypt(nonce, ct_tag, aad)
    except Exception:
        return None
