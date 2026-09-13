/**
 * @latticeagi/bedrock — MIT OSS core SDK (spec §8.2).
 * Pure functions and the HTTP client. No reusable ALLOW token, no mutable
 * policy handle, no default-allow mode, no dispatch during replay.
 */
export { BedrockError, apiError, httpStatusFor, exitCodeFor, NotImplementedError } from "./errors.js";
export type { ErrorCode } from "./errors.js";
export { canonicalString, canonicalKeyOrder, parseJson, parseJsonBytes, J } from "./canon.js";
export type { Json } from "./canon.js";
export { parseYaml } from "./yaml.js";
export { D, S, sha256Hex, ed25519PublicKey, ed25519Sign, ed25519Verify, signObject, verifyObject, b64urlDecode, b64urlEncode, hexDecode } from "./crypto.js";
export { compile, pinOf, manifestDigestOrThrow } from "./compiler.js";
export { evaluate, checkArgs } from "./evaluator.js";
export { verifyBundle, verifyPinUpdateSignatures, checkSignatures, canonicalEqual } from "./bundle.js";
export { verifyEvidence } from "./evidence.js";
export { semanticDiff } from "./diff.js";
export { BedrockClient, ApiError } from "./client.js";
export type { ClientOptions } from "./client.js";
export { Store } from "./server/storage.js";
export { BedrockTenantDO, CrashFault } from "./server/tenant.js";
export type { DoDeps, DoSecrets, Inbound, DoResponse } from "./server/tenant.js";
export { LocalEmulator } from "./server/http.js";
export { workerFetch } from "./server/worker.js";
export { MemoryRecordsAdapter, FixtureRecordsAdapter } from "./server/adapter.js";
export type { RecordsAdapter } from "./server/adapter.js";
export * as hosted from "./hosted.js";
export * as fixtures from "./fixtures.js";
export type * from "./types.js";
