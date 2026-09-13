"""Bedrock error codes (spec §4.4). Mirrors src/errors.ts."""

CODES = (
    "PARSE", "SCHEMA", "LIMIT", "AUTH_REQUIRED", "FORBIDDEN", "NOT_FOUND",
    "UNSUPPORTED_VERSION", "SIGNATURE_INVALID", "SIGNATURE_DUPLICATE",
    "KEY_UNKNOWN", "QUORUM", "HASH_MISMATCH", "VERSION_CONFLICT",
    "REVISION_CONFLICT", "PIN_NOT_HEAD", "PIN_EXPIRED",
    "IDEMPOTENCY_CONFLICT", "REQUEST_ID_REUSED", "INSTANCE_STALE",
    "INSTANCE_MISMATCH", "COUNTER_CONFLICT", "PAUSED", "UNPINNED",
    "POLICY_INACTIVE", "MANIFEST_UNAVAILABLE", "CLOCK_UNSAFE",
    "AUDIT_UNAVAILABLE", "STORAGE_FULL", "BUSY", "UNSUPPORTED_COMPOSITION",
    "STATE_TRANSITION",
)

RETRYABLE = frozenset(
    ("BUSY", "INSTANCE_STALE", "INSTANCE_MISMATCH", "AUDIT_UNAVAILABLE")
)


class BedrockError(Exception):
    """Error carrying a spec error code; `status_override` for e.g. 405."""

    def __init__(self, code: str, message: str | None = None, status_override: int | None = None):
        super().__init__(message or code)
        if code not in CODES:
            raise ValueError(f"unknown error code {code}")
        self.code = code
        self.audit_seq: int | None = None
        self.status_override = status_override

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE


def api_error(code: str, audit_seq: int | None = None) -> dict:
    return {
        "error": {
            "code": code,
            "retryable": code in RETRYABLE,
            "audit_seq": audit_seq,
        }
    }


def http_status_for(code: str) -> int:
    if code in ("PARSE", "SCHEMA"):
        return 400
    if code == "AUTH_REQUIRED":
        return 401
    if code == "FORBIDDEN":
        return 403
    if code == "NOT_FOUND":
        return 404
    if code in (
        "VERSION_CONFLICT", "REVISION_CONFLICT", "PIN_NOT_HEAD",
        "IDEMPOTENCY_CONFLICT", "REQUEST_ID_REUSED", "COUNTER_CONFLICT",
        "STATE_TRANSITION",
    ):
        return 409
    if code == "LIMIT":
        return 413
    if code in (
        "UNSUPPORTED_VERSION", "SIGNATURE_INVALID", "SIGNATURE_DUPLICATE",
        "KEY_UNKNOWN", "QUORUM", "HASH_MISMATCH", "PIN_EXPIRED",
        "UNSUPPORTED_COMPOSITION",
    ):
        return 422
    if code == "BUSY":
        return 429
    return 503


def exit_code_for(code: str) -> int:
    if code in ("PARSE", "SCHEMA", "LIMIT", "UNSUPPORTED_VERSION", "UNSUPPORTED_COMPOSITION"):
        return 2
    if code in (
        "SIGNATURE_INVALID", "SIGNATURE_DUPLICATE", "KEY_UNKNOWN",
        "QUORUM", "HASH_MISMATCH", "PIN_EXPIRED",
    ):
        return 4
    if code in ("AUTH_REQUIRED", "FORBIDDEN"):
        return 5
    if code in (
        "VERSION_CONFLICT", "REVISION_CONFLICT", "PIN_NOT_HEAD",
        "IDEMPOTENCY_CONFLICT", "REQUEST_ID_REUSED", "COUNTER_CONFLICT",
        "STATE_TRANSITION",
    ):
        return 6
    if code == "NOT_FOUND":
        return 10
    return 7


class NotImplementedSurface(Exception):
    """Hosted/paid surfaces specified but not part of the MIT core."""

    def __init__(self, surface: str):
        super().__init__(
            f"{surface} is part of the hosted LatticeAG registry surface and is "
            "not implemented in the MIT core. See "
            "https://github.com/LatticeAG/bedrock for the hosted registry pilot."
        )
