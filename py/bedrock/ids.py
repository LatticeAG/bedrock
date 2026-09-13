"""Bedrock ID grammar: ^PREFIX_[A-Za-z0-9_-]{21}$ with locked alphabet."""
import re
import secrets

from .errors import BedrockError

ID_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz-"
ID_SUFFIX_LEN = 21
PREFIXES = ("bte", "bch", "bgw", "bin", "bpr", "bky", "brq", "brl", "bds", "blg")

ID_RE = re.compile(r"^(" + "|".join(PREFIXES) + r")_[A-Za-z0-9_-]{21}$")


def is_bedrock_id(s: str) -> bool:
    return bool(ID_RE.match(s))


def new_id(prefix: str) -> str:
    return f"{prefix}_{nanoid_suffix()}"


def nanoid_suffix() -> str:
    return "".join(ID_ALPHABET[b & 63] for b in secrets.token_bytes(ID_SUFFIX_LEN))


def fixed_id(prefix: str, c: str) -> str:
    if len(c) != 1 or c not in ID_ALPHABET:
        raise BedrockError("SCHEMA", "bad fixture id char")
    return f"{prefix}_{c * ID_SUFFIX_LEN}"
