"""Strict YAML subset parser (spec §3.2 / §9.3). Mirrors src/yaml.ts.

Accepted: exactly one YAML 1.2 document over the JSON scalar subset, UTF-8.
Rejected: aliases, anchors, merge keys, custom tags, directives, implicit
timestamps, non-string mapping keys, duplicate keys, block scalars, tabs in
indentation, non-NFC strings, ambiguous plain scalars.
"""
from __future__ import annotations

import re
import unicodedata

from .errors import BedrockError
from .canon import MAX_DEPTH, MAX_MEMBERS, SAFE_INT_MAX


def _fail(msg: str):
    raise BedrockError("PARSE", msg)


INT_TOKEN = re.compile(r"^-?(0|[1-9][0-9]*)$")
FLOATISH = re.compile(r"^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$")
AMBIGUOUS_BOOL_NULL = re.compile(r"^(y|n|yes|no|on|off|true|false|null|~)$", re.I)
DATE_LIKE = re.compile(r"^\d{4}-\d{1,2}-\d{1,2}([Tt ].*)?$")
OTHER_AMBIGUOUS = re.compile(r"^(\.|[-+]?\.|0x|0o|0b|\d+:|\d*\.?\d+[eE]|[-+]?\.inf|\.nan)", re.I)


def _check_nfc(s: str) -> str:
    if unicodedata.normalize("NFC", s) != s:
        _fail("string is not NFC")
    return s


def _resolve_plain(raw: str):
    if raw == "":
        _fail("empty plain scalar")
    if raw == "null":
        return None
    if raw == "true":
        return True
    if raw == "false":
        return False
    if INT_TOKEN.match(raw):
        n = int(raw)
        if abs(n) > SAFE_INT_MAX:
            _fail("integer outside safe range")
        return n
    if AMBIGUOUS_BOOL_NULL.match(raw):
        _fail(f"ambiguous plain scalar {raw!r} (quote it for a string)")
    if FLOATISH.match(raw) or OTHER_AMBIGUOUS.match(raw) or DATE_LIKE.match(raw):
        _fail(f"numeric/date-looking plain scalar {raw!r} outside the JSON subset")
    return _check_nfc(raw)


def _resolve_key(raw: str, quoted: bool) -> str:
    if quoted:
        return _check_nfc(raw)
    v = _resolve_plain(raw)
    if not isinstance(v, str):
        _fail("non-string mapping key")
    return v


# ---------------------------------------------------------------------------
# Line-level preprocessing
# ---------------------------------------------------------------------------


def _strip_comment(line: str) -> str:
    in_s = in_d = False
    i = 0
    while i < len(line):
        c = line[i]
        if in_s:
            if c == "'":
                if i + 1 < len(line) and line[i + 1] == "'":
                    i += 1
                else:
                    in_s = False
            i += 1
            continue
        if in_d:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_d = False
            i += 1
            continue
        if c == "'":
            in_s = True
        elif c == '"':
            in_d = True
        elif c == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
        i += 1
    return line


def _preprocess(text: str) -> list:
    lines = []
    doc_seen = doc_ended = False
    for raw in re.split(r"\r?\n", text):
        if raw.startswith("\t") or re.match(r"^ +\t", raw):
            _fail("tab in indentation")
        trimmed = _strip_comment(raw).rstrip(" ")
        if trimmed.strip(" ") == "":
            continue
        indent = len(trimmed) - len(trimmed.lstrip(" "))
        content = trimmed[indent:]
        if content.startswith("%"):
            _fail("YAML directives forbidden")
        if content == "---":
            if doc_seen:
                _fail("exactly one YAML document required")
            doc_seen = True
            continue
        if content == "...":
            doc_ended = True
            continue
        if doc_ended:
            _fail("content after document end")
        if content.startswith("---") or content.startswith("..."):
            _fail("unexpected document marker")
        lines.append((indent, content))
    return lines


# ---------------------------------------------------------------------------
# Flow parsing
# ---------------------------------------------------------------------------


class _Flow:
    def __init__(self, s: str):
        self.s = s
        self.i = 0

    def ws(self):
        while self.i < len(self.s) and self.s[self.i] == " ":
            self.i += 1

    def peek(self):
        return self.s[self.i] if self.i < len(self.s) else None

    def value(self):
        self.ws()
        c = self.peek()
        if c == "{":
            return self.flow_map()
        if c == "[":
            return self.flow_seq()
        if c == '"':
            return self.double_quoted()
        if c == "'":
            return self.single_quoted()
        if c in ("&", "*", "!"):
            _fail("anchors/aliases/tags forbidden")
        return self.plain()

    def plain(self):
        start = self.i
        while self.i < len(self.s):
            if self.s[self.i] in ",}]":
                break
            self.i += 1
        raw = self.s[start:self.i].rstrip(" ")
        return _resolve_plain(raw)

    def single_quoted(self) -> str:
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.s):
                _fail("unterminated single-quoted scalar")
            c = self.s[self.i]
            if c == "'":
                if self.i + 1 < len(self.s) and self.s[self.i + 1] == "'":
                    out.append("'")
                    self.i += 2
                    continue
                self.i += 1
                break
            out.append(c)
            self.i += 1
        return _check_nfc("".join(out))

    def double_quoted(self) -> str:
        self.i += 1
        out = []
        while True:
            if self.i >= len(self.s):
                _fail("unterminated double-quoted scalar")
            c = self.s[self.i]
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                self.i += 1
                if self.i >= len(self.s):
                    _fail("unterminated escape")
                e = self.s[self.i]
                self.i += 1
                simple = {
                    '"': '"', "\\": "\\", "/": "/", "b": "\b",
                    "f": "\f", "n": "\n", "r": "\r", "t": "\t",
                }
                if e in simple:
                    out.append(simple[e])
                elif e == "u":
                    h1 = self.s[self.i:self.i + 4]
                    if len(h1) != 4 or not re.match(r"^[0-9a-fA-F]{4}$", h1):
                        _fail("bad \\u escape")
                    self.i += 4
                    u1 = int(h1, 16)
                    if 0xD800 <= u1 <= 0xDBFF:
                        if self.i + 1 >= len(self.s) or self.s[self.i] != "\\" or self.s[self.i + 1] != "u":
                            _fail("lone surrogate")
                        h2 = self.s[self.i + 2:self.i + 6]
                        if not re.match(r"^[0-9a-fA-F]{4}$", h2 or ""):
                            _fail("bad \\u escape")
                        u2 = int(h2, 16)
                        if not 0xDC00 <= u2 <= 0xDFFF:
                            _fail("lone surrogate")
                        self.i += 6
                        out.append(chr(0x10000 + ((u1 - 0xD800) << 10) + (u2 - 0xDC00)))
                    elif 0xDC00 <= u1 <= 0xDFFF:
                        _fail("lone surrogate")
                    else:
                        out.append(chr(u1))
                else:
                    _fail(f"escape \\{e} outside the JSON subset")
                continue
            if ord(c) < 0x20:
                _fail("unescaped control character")
            out.append(c)
            self.i += 1
        return _check_nfc("".join(out))

    def flow_map(self) -> dict:
        self.i += 1
        obj: dict = {}
        self.ws()
        if self.peek() == "}":
            self.i += 1
            return obj
        while True:
            self.ws()
            c = self.peek()
            if c == '"':
                key = self.double_quoted()
            elif c == "'":
                key = self.single_quoted()
            else:
                start = self.i
                while self.i < len(self.s) and self.s[self.i] != ":":
                    self.i += 1
                raw = self.s[start:self.i].rstrip(" ")
                if raw == "<<":
                    _fail("merge keys forbidden")
                key = _resolve_key(raw, False)
            if key == "<<":
                _fail("merge keys forbidden")
            self.ws()
            if self.peek() != ":":
                _fail("expected ':' in flow mapping")
            self.i += 1
            if key in obj:
                _fail("duplicate mapping key")
            obj[key] = self.value()
            self.ws()
            d = self.peek()
            if d == ",":
                self.i += 1
                continue
            if d == "}":
                self.i += 1
                break
            _fail("expected ',' or '}'")
        if len(obj) > MAX_MEMBERS:
            _fail("object member count > 1024")
        return obj

    def flow_seq(self) -> list:
        self.i += 1
        arr: list = []
        self.ws()
        if self.peek() == "]":
            self.i += 1
            return arr
        while True:
            arr.append(self.value())
            self.ws()
            d = self.peek()
            if d == ",":
                self.i += 1
                continue
            if d == "]":
                self.i += 1
                break
            _fail("expected ',' or ']'")
        return arr


# ---------------------------------------------------------------------------
# Block parsing
# ---------------------------------------------------------------------------


def parse_yaml(text: str):
    lines = _preprocess(text)
    if not lines:
        _fail("empty document")
    p = _Block(lines)
    v = p.parse_block(0)
    if p.pos != len(lines):
        _fail("unexpected trailing/indented content")
    return v


def parse_yaml_bytes(data: bytes):
    if data[:3] == b"\xef\xbb\xbf":
        _fail("UTF-8 BOM not allowed")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        _fail("invalid UTF-8")
    return parse_yaml(text)


class _Block:
    def __init__(self, lines):
        self.lines = lines
        self.pos = 0

    @property
    def cur(self):
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def parse_block(self, depth: int):
        indent, text = self.cur
        if text == "-" or text.startswith("- "):
            return self.parse_seq(indent, depth)
        if _looks_like_map_entry(text):
            return self.parse_map(indent, depth)
        fp = _Flow(text)
        v = fp.value()
        fp.ws()
        if fp.i != len(text):
            _fail("trailing content in scalar")
        self.pos += 1
        return v

    def parse_seq(self, indent: int, depth: int) -> list:
        if depth > MAX_DEPTH:
            _fail("nesting depth > 16")
        arr = []
        while True:
            line = self.cur
            if line is None or line[0] != indent:
                break
            text = line[1]
            if not (text == "-" or text.startswith("- ")):
                break
            content_col = indent + 1 if text == "-" else indent + 2
            rest = "" if text == "-" else text[2:]
            self.pos += 1
            if rest == "":
                nxt = self.cur
                if nxt is not None and nxt[0] >= content_col:
                    arr.append(self.parse_block(depth + 1))
                else:
                    arr.append(None)
                continue
            if _looks_like_map_entry(rest):
                arr.append(self.parse_inline_map(content_col, rest, depth))
            else:
                fp = _Flow(rest)
                v = fp.value()
                fp.ws()
                if fp.i != len(rest):
                    _fail("trailing content in sequence item")
                arr.append(v)
        return arr

    def parse_inline_map(self, col: int, first_text: str, depth: int) -> dict:
        if depth + 1 > MAX_DEPTH:
            _fail("nesting depth > 16")
        obj: dict = {}
        self.map_entry(obj, first_text, col, depth)
        while True:
            nxt = self.cur
            if nxt is not None and nxt[0] == col and _looks_like_map_entry(nxt[1]):
                self.pos += 1
                self.map_entry(obj, nxt[1], col, depth)
                continue
            break
        if len(obj) > MAX_MEMBERS:
            _fail("object member count > 1024")
        return obj

    def parse_map(self, indent: int, depth: int) -> dict:
        if depth + 1 > MAX_DEPTH:
            _fail("nesting depth > 16")
        obj: dict = {}
        while True:
            line = self.cur
            if line is None or line[0] != indent or not _looks_like_map_entry(line[1]):
                break
            self.pos += 1
            self.map_entry(obj, line[1], indent, depth)
        if len(obj) > MAX_MEMBERS:
            _fail("object member count > 1024")
        return obj

    def map_entry(self, obj: dict, text: str, col: int, depth: int):
        key, rest = _split_key(text)
        if key == "<<":
            _fail("merge keys forbidden")
        if key in obj:
            _fail("duplicate mapping key")
        if rest != "":
            fp = _Flow(rest)
            v = fp.value()
            fp.ws()
            if fp.i != len(rest):
                _fail("trailing content after value")
            obj[key] = v
            return
        nxt = self.cur
        if nxt is not None and nxt[0] > col:
            obj[key] = self.parse_block(depth + 1)
            return
        if nxt is not None and nxt[0] == col and (nxt[1] == "-" or nxt[1].startswith("- ")):
            obj[key] = self.parse_seq(col, depth + 1)
            return
        obj[key] = None


def _split_key(text: str):
    if text[0] in "\"'":
        fp = _Flow(text)
        key = fp.double_quoted() if text[0] == '"' else fp.single_quoted()
        fp.ws()
        if fp.peek() != ":":
            _fail("expected ':' after quoted key")
        fp.i += 1
        rest = text[fp.i:]
        if rest.startswith(" "):
            rest = rest[1:]
        return key, rest
    for i, c in enumerate(text):
        if c == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            raw = text[:i].rstrip(" ")
            key = _resolve_key(raw, False)
            rest = text[i + 1:]
            if rest.startswith(" "):
                rest = rest[1:]
            return key, rest
    _fail("expected mapping entry")


def _looks_like_map_entry(text: str) -> bool:
    if not text:
        return False
    if text[0] in "\"'":
        fp = _Flow(text)
        try:
            if text[0] == '"':
                fp.double_quoted()
            else:
                fp.single_quoted()
            fp.ws()
            return fp.peek() == ":"
        except BedrockError:
            return False
    if text == "-" or text.startswith("- "):
        return False
    for i, c in enumerate(text):
        if c == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            return True
        if c in " {#[":
            return False
        if c in "&*!?|>":
            _fail("anchors/aliases/tags/block scalars forbidden")
    return False
