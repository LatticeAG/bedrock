"""Bedrock Time: exactly YYYY-MM-DDTHH:mm:ss.sssZ, valid Gregorian date."""
import calendar
import re
from datetime import datetime, timezone

from .errors import BedrockError

TIME_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$")


def is_time(s: str) -> bool:
    m = TIME_RE.match(s)
    if not m:
        return False
    y, mo, d, h, mi, sec, _ = (int(g) for g in m.groups())
    if not 1 <= mo <= 12 or h > 23 or mi > 59 or sec > 59:
        return False
    return 1 <= d <= calendar.monthrange(y, mo)[1]


def parse_time(s: str) -> int:
    """Epoch milliseconds."""
    if not is_time(s):
        raise BedrockError("SCHEMA", f"invalid Time: {s!r}")
    m = TIME_RE.match(s)
    y, mo, d, h, mi, sec, ms = (int(g) for g in m.groups())
    dt = datetime(y, mo, d, h, mi, sec, ms * 1000, tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def format_time(ms: int) -> str:
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"
