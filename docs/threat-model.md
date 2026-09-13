# Threat model review artifact (P0)

Scope: the MIT core — signed charter files, exact pins, the local gateway,
RECORDS adapter boundary, audit log, fleet heartbeats, advisory disputes.

## Adversaries

- **Compromised hosted operator** — can censor, delay, or serve divergent
  views. Mitigations: client-held trust root, threshold charter signatures,
  caller-verifiable checkpoints, exact pins exposing some (not all)
  misbehavior. A standalone `/check` response is advisory and cannot cross a
  trust barrier as an approval ticket.
- **Network/MITM attacker** — mitigated by TLS termination at the Worker plus
  content-level signatures; the local emulator is plaintext localhost only and
  never a production posture.
- **Malicious caller** — bearer auth, role checks before idempotency,
  closed-schema request validation, fail-closed evaluation (deny dominates,
  missing coverage denies, parse uncertainty never becomes allow).
- **Stale/forged fleet node** — credential-bound instance identity, sequential
  counters, fixed inventory, 180 s receipt expiry. A heartbeat is software
  freshness evidence, never hardware attestation.
- **Signer compromise** — pause is unilateral; successor charters require the
  pinned next_authority threshold; rotation is by successor, not revocation.

## Explicit non-goals / residual risks

- Registry censorship is detectable only relative to caller-held checkpoints;
  truncation relative to an external checkpoint is detectable, not globally
  impossible.
- The upstream is protected only when it has no alternate ingress; a
  deployment where the upstream can be reached directly is advisory-only and
  must not be described as gateway-protected.
- Audit output bodies are encrypted at rest (`output_enc`/`response_enc`,
  AES-256-GCM with tenant-held keys); Bedrock is not a general secrets store.
- Disputes are immutable advisory text; they cannot alter evaluation, grant
  exceptions, or produce executable law.

## Fail-closed invariants

- No dispatch without a preceding committed signed `CallDispatched` entry.
- Crash after marker and before invocation resolves `INDETERMINATE`, never
  resends.
- Audit append failure fails the request closed (`AUDIT_UNAVAILABLE`, 503).
- Storage pressure, clock unsafety, and manifest unavailability all deny.
