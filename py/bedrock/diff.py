"""Semantic diff (spec §8.1). Mirrors src/diff.ts: RFC6901 paths sorted
bytewise; additions/deletions use null; array differences report whole array."""
from __future__ import annotations

from .canon import canonical_string


def _escape(seg: str) -> str:
    return seg.replace("~", "~0").replace("/", "~1")


def _walk(prefix: str, before, after, out: list):
    if canonical_string(before) == canonical_string(after):
        return
    if isinstance(before, dict) and isinstance(after, dict):
        keys = set(before) | set(after)
        for k in sorted(keys):
            p = prefix + "/" + _escape(k)
            _walk(
                p,
                before[k] if k in before else None,
                after[k] if k in after else None,
                out,
            )
        return
    out.append({"path": prefix, "before": before, "after": after})


def semantic_diff(before, after) -> list:
    out: list = []
    _walk("", before, after, out)
    return sorted(out, key=lambda c: c["path"])
