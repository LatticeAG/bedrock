"""RFC 8785 canonicalization over the restricted Bedrock JSON domain.

Mirrors src/canon.ts: integers only, NFC strings, closed objects, member
order by UTF-16 code units. Python strings are code points, so ordering uses
the UTF-16BE byte encoding — identical to JS code-unit comparison.
"""
from __future__ import annotations

import unicodedata

from .errors import BedrockError

Json = None | bool | int | str | list | dict

MAX_DEPTH = 16
MAX_MEMBERS = 1024
SAFE_INT_MAX = 9007199254740991


def _utf16_key(s: str) -> bytes:
    return s.encode("utf-16-be")


def utf16_key_compare(a: str, b: str) -> int:
    ka, kb = _utf16_key(a), _utf16_key(b)
    return (ka > kb) - (ka < kb)


def canonical_string(v) -> str:
    return _into(v, 0)


def _into(v, depth: int) -> str:
    if depth > MAX_DEPTH:
        raise BedrockError("LIMIT", "nesting depth > 16")
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):  # bool handled above
        return _num(v)
    if isinstance(v, str):
        return _str(v)
    if isinstance(v, (list, tuple)):
        return "[" + ",".join(_into(e, depth + 1) for e in v) + "]"
    if isinstance(v, dict):
        if len(v) > MAX_MEMBERS:
            raise BedrockError("LIMIT", "object member count > 1024")
        keys = sorted(v.keys(), key=_utf16_key)
        return "{" + ",".join(
            _str(k) + ":" + _into(v[k], depth + 1) for k in keys
        ) + "}"
    raise BedrockError("SCHEMA", "unsupported JSON value")


def _num(n: int) -> str:
    if not isinstance(n, int) or isinstance(n, bool):
        raise BedrockError("SCHEMA", "non-integer numbers are outside the Bedrock domain")
    if abs(n) > SAFE_INT_MAX:
        raise BedrockError("SCHEMA", "integer outside safe range")
    return str(n)


_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t",
    "\n": "\\n", "\f": "\\f", "\r": "\\r",
}


def _str(s: str) -> str:
    out = '"'
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc is not None:
            out += esc
        elif ord(ch) < 0x20:
            out += "\\u%04x" % ord(ch)
        else:
            out += ch
    return out + '"'


def J(v) -> bytes:
    """J(x): canonical UTF-8 bytes of x."""
    return canonical_string(v).encode("utf-8")


def canonical_key_order(obj: dict) -> list:
    return sorted(obj.keys(), key=_utf16_key)


# ---------------------------------------------------------------------------
# Strict JSON parsing: UTF-8, no BOM, no duplicate keys, no lone surrogates,
# integer-only numeric tokens, depth/member bounds, NFC strings.
# ---------------------------------------------------------------------------


def parse_json_bytes(data: bytes):
    if data[:3] == b"\xef\xbb\xbf":
        raise BedrockError("PARSE", "UTF-8 BOM not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise BedrockError("PARSE", "invalid UTF-8")
    return parse_json(text)


def parse_json(text: str):
    p = _Parser(text)
    v = p.value(0)
    p.skip_ws()
    if not p.eof():
        raise BedrockError("PARSE", "trailing bytes after JSON value")
    return v


def _check_nfc(s: str) -> str:
    if unicodedata.normalize("NFC", s) != s:
        raise BedrockError("PARSE", "string is not NFC")
    return s


class _Parser:
    def __init__(self, s: str):
        self.s = s
        self.i = 0

    def eof(self) -> bool:
        return self.i >= len(self.s)

    def peek(self) -> int:
        return ord(self.s[self.i]) if self.i < len(self.s) else -1

    def skip_ws(self):
        while self.i < len(self.s) and self.s[self.i] in " \t\n\r":
            self.i += 1

    def fail(self, msg):
        raise BedrockError("PARSE", msg)

    def value(self, depth: int):
        if depth > MAX_DEPTH:
            self.fail("nesting depth > 16")
        self.skip_ws()
        c = self.peek()
        if c == 0x7B:
            return self.obj(depth)
        if c == 0x5B:
            return self.arr(depth)
        if c == 0x22:
            return self.string()
        if c == 0x74:
            return self.lit("true", True)
        if c == 0x66:
            return self.lit("false", False)
        if c == 0x6E:
            return self.lit("null", None)
        if c == 0x2D or 0x30 <= c <= 0x39:
            return self.number()
        self.fail("unexpected token")

    def lit(self, word: str, v):
        if not self.s.startswith(word, self.i):
            self.fail("bad literal")
        self.i += len(word)
        return v

    def number(self) -> int:
        start = self.i
        if self.peek() == 0x2D:
            self.i += 1
        if self.peek() == 0x30:
            self.i += 1
        elif 0x31 <= self.peek() <= 0x39:
            while 0x30 <= self.peek() <= 0x39:
                self.i += 1
        else:
            self.fail("bad number")
        c = self.peek()
        if c in (0x2E, 0x65, 0x45, 0x2B):
            self.fail("non-integer numeric token")
        raw = self.s[start:self.i]
        if raw == "-0":
            self.fail("negative zero rejected")
        n = int(raw)
        if abs(n) > SAFE_INT_MAX:
            self.fail("integer outside safe range")
        return n

    def string(self) -> str:
        self.i += 1  # opening quote
        out = []
        while True:
            if self.eof():
                self.fail("unterminated string")
            c = self.s[self.i]
            o = ord(c)
            if o == 0x22:
                self.i += 1
                break
            if o == 0x5C:
                self.i += 1
                if self.eof():
                    self.fail("unterminated escape")
                e = self.s[self.i]
                self.i += 1
                if e == '"':
                    out.append('"')
                elif e == "\\":
                    out.append("\\")
                elif e == "/":
                    out.append("/")
                elif e == "b":
                    out.append("\b")
                elif e == "f":
                    out.append("\f")
                elif e == "n":
                    out.append("\n")
                elif e == "r":
                    out.append("\r")
                elif e == "t":
                    out.append("\t")
                elif e == "u":
                    h1 = self.s[self.i:self.i + 4]
                    if len(h1) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in h1):
                        self.fail("bad \\u escape")
                    self.i += 4
                    u1 = int(h1, 16)
                    if 0xD800 <= u1 <= 0xDBFF:
                        if self.i + 1 >= len(self.s) or self.s[self.i] != "\\" or self.s[self.i + 1] != "u":
                            self.fail("lone surrogate")
                        h2 = self.s[self.i + 2:self.i + 6]
                        if len(h2) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in h2):
                            self.fail("bad \\u escape")
                        u2 = int(h2, 16)
                        if not 0xDC00 <= u2 <= 0xDFFF:
                            self.fail("lone surrogate")
                        self.i += 6
                        out.append(chr(0x10000 + ((u1 - 0xD800) << 10) + (u2 - 0xDC00)))
                    elif 0xDC00 <= u1 <= 0xDFFF:
                        self.fail("lone surrogate")
                    else:
                        out.append(chr(u1))
                else:
                    self.fail("bad escape")
                continue
            if o < 0x20:
                self.fail("unescaped control character")
            if 0xD800 <= o <= 0xDFFF:
                self.fail("lone surrogate")
            out.append(c)
            self.i += 1
        s = "".join(out)
        return _check_nfc(s)

    def obj(self, depth: int) -> dict:
        self.i += 1
        out: dict = {}
        self.skip_ws()
        if self.peek() == 0x7D:
            self.i += 1
            return out
        while True:
            self.skip_ws()
            if self.peek() != 0x22:
                self.fail("object key must be a string")
            key = self.string()
            if key in out:
                self.fail("duplicate object member")
            self.skip_ws()
            if self.peek() != 0x3A:
                self.fail("expected ':'")
            self.i += 1
            out[key] = self.value(depth + 1)
            if len(out) > MAX_MEMBERS:
                self.fail("object member count > 1024")
            self.skip_ws()
            c = self.peek()
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x7D:
                self.i += 1
                return out
            self.fail("expected ',' or '}'")

    def arr(self, depth: int) -> list:
        self.i += 1
        out: list = []
        self.skip_ws()
        if self.peek() == 0x5D:
            self.i += 1
            return out
        while True:
            out.append(self.value(depth + 1))
            self.skip_ws()
            c = self.peek()
            if c == 0x2C:
                self.i += 1
                continue
            if c == 0x5D:
                self.i += 1
                return out
            self.fail("expected ',' or ']'")


def assert_canonical_json(v, max_bytes: int) -> None:
    s = canonical_string(v)
    if len(s.encode("utf-8")) > max_bytes:
        raise BedrockError("LIMIT", "canonical bytes bound exceeded")
