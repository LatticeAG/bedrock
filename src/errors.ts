/** Bedrock error codes (spec §4.4). */
export type ErrorCode =
  | "PARSE" | "SCHEMA" | "LIMIT" | "AUTH_REQUIRED" | "FORBIDDEN" | "NOT_FOUND"
  | "UNSUPPORTED_VERSION" | "SIGNATURE_INVALID" | "SIGNATURE_DUPLICATE" | "KEY_UNKNOWN" | "QUORUM"
  | "HASH_MISMATCH" | "VERSION_CONFLICT" | "REVISION_CONFLICT" | "PIN_NOT_HEAD" | "PIN_EXPIRED"
  | "IDEMPOTENCY_CONFLICT" | "REQUEST_ID_REUSED" | "INSTANCE_STALE" | "INSTANCE_MISMATCH"
  | "COUNTER_CONFLICT" | "PAUSED" | "UNPINNED" | "POLICY_INACTIVE" | "MANIFEST_UNAVAILABLE"
  | "CLOCK_UNSAFE" | "AUDIT_UNAVAILABLE" | "STORAGE_FULL" | "BUSY" | "UNSUPPORTED_COMPOSITION"
  | "STATE_TRANSITION";

const RETRYABLE = new Set<ErrorCode>([
  "BUSY", "INSTANCE_STALE", "INSTANCE_MISMATCH", "AUDIT_UNAVAILABLE",
]);

export class BedrockError extends Error {
  readonly code: ErrorCode;
  /** Audit sequence of a CommandRejected entry, when one was appended. */
  auditSeq: number | null = null;
  /** HTTP status override (e.g. 405 SCHEMA for an unsupported method). */
  statusOverride: number | null = null;
  constructor(code: ErrorCode, message?: string, statusOverride?: number) {
    super(message ?? code);
    this.name = "BedrockError";
    this.code = code;
    if (statusOverride !== undefined) this.statusOverride = statusOverride;
  }
  get retryable(): boolean {
    return RETRYABLE.has(this.code);
  }
}

export function apiError(code: ErrorCode, auditSeq: number | null = null): {
  error: { code: ErrorCode; retryable: boolean; audit_seq: number | null };
} {
  return { error: { code, retryable: RETRYABLE.has(code), audit_seq: auditSeq } };
}

/** HTTP status mapping per spec §7.1. */
export function httpStatusFor(code: ErrorCode): number {
  switch (code) {
    case "PARSE":
    case "SCHEMA":
      return 400;
    case "AUTH_REQUIRED":
      return 401;
    case "FORBIDDEN":
      return 403;
    case "NOT_FOUND":
      return 404;
    case "VERSION_CONFLICT":
    case "REVISION_CONFLICT":
    case "PIN_NOT_HEAD":
    case "IDEMPOTENCY_CONFLICT":
    case "REQUEST_ID_REUSED":
    case "COUNTER_CONFLICT":
    case "STATE_TRANSITION":
      return 409;
    case "LIMIT":
      return 413;
    case "UNSUPPORTED_VERSION":
    case "SIGNATURE_INVALID":
    case "SIGNATURE_DUPLICATE":
    case "KEY_UNKNOWN":
    case "QUORUM":
    case "HASH_MISMATCH":
    case "PIN_EXPIRED":
    case "UNSUPPORTED_COMPOSITION":
      return 422;
    case "BUSY":
      return 429;
    case "INSTANCE_STALE":
    case "INSTANCE_MISMATCH":
    case "PAUSED":
    case "UNPINNED":
    case "POLICY_INACTIVE":
    case "MANIFEST_UNAVAILABLE":
    case "CLOCK_UNSAFE":
    case "AUDIT_UNAVAILABLE":
    case "STORAGE_FULL":
      return 503;
  }
}

/** CLI exit mapping per spec §8.1. */
export function exitCodeFor(code: ErrorCode): number {
  switch (code) {
    case "PARSE":
    case "SCHEMA":
    case "LIMIT":
    case "UNSUPPORTED_VERSION":
    case "UNSUPPORTED_COMPOSITION":
      return 2;
    case "SIGNATURE_INVALID":
    case "SIGNATURE_DUPLICATE":
    case "KEY_UNKNOWN":
    case "QUORUM":
    case "HASH_MISMATCH":
    case "PIN_EXPIRED":
      return 4;
    case "AUTH_REQUIRED":
    case "FORBIDDEN":
      return 5;
    case "VERSION_CONFLICT":
    case "REVISION_CONFLICT":
    case "PIN_NOT_HEAD":
    case "IDEMPOTENCY_CONFLICT":
    case "REQUEST_ID_REUSED":
    case "COUNTER_CONFLICT":
    case "STATE_TRANSITION":
      return 6;
    case "BUSY":
    case "INSTANCE_STALE":
    case "INSTANCE_MISMATCH":
    case "PAUSED":
    case "UNPINNED":
    case "POLICY_INACTIVE":
    case "MANIFEST_UNAVAILABLE":
    case "CLOCK_UNSAFE":
    case "AUDIT_UNAVAILABLE":
    case "STORAGE_FULL":
      return 7;
    case "NOT_FOUND":
      return 10;
  }
}

/** Raised by hosted/paid surfaces that are specified but not part of the MIT core. */
export class NotImplementedError extends Error {
  constructor(surface: string) {
    super(
      `${surface} is part of the hosted LatticeAG registry surface and is not ` +
        `implemented in the MIT core. See https://github.com/LatticeAG/bedrock ` +
        `for the hosted registry pilot.`,
    );
    this.name = "NotImplementedError";
  }
}
