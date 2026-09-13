# Bedrock

[![CI](https://github.com/LatticeAG/bedrock/actions/workflows/ci.yml/badge.svg)](https://github.com/LatticeAG/bedrock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Conformance: TV-B--01..55](https://img.shields.io/badge/conformance-TV--B--01..55-green)](conformance/)

Versioned signed charters, exact version pins, gateway allow/deny, advisory disputes, audit, and fleet split detection for tool-using agents.

Bedrock gives operators a signed YAML policy file, a deterministic evaluator, and a mandatory gateway that durably records every authorization decision before an upstream tool is invoked. There is no `latest`: every admitted call names an exact charter/manifest/engine tuple, explicit deny always dominates scope allow, and missing coverage denies.

- **MIT core** — schemas, canonicalization, signatures, compiler, evaluator, CLI, TypeScript and Python SDKs, Worker/Durable-Object gateway, registry handlers, audit verifier, and fleet detector.
- **Hosted surface** — the only paid component is the hosted charter registry (managed deployment, authenticated tenant storage, availability). It runs the same contracts and is not a new trust root; caller-pinned roots and threshold verification remain mandatory.

## Install

```bash
npm install @latticeagi/bedrock   # TypeScript SDK + `bedrock` CLI
pip install latticeagi-bedrock   # Python SDK + `python -m bedrock` CLI
```

TypeScript requires Node.js >= 22.5 (uses `node:sqlite` and WebCrypto-compatible Ed25519). Python requires >= 3.11 and `cryptography` (AES-256-GCM; Ed25519 is implemented in-package for identical canonicality checks).

## Quick start

```bash
# Lint and sign a charter source file
bedrock charter lint charter.yaml --manifest manifest.json --root trust.json --json
bedrock charter sign charter.yaml --manifest manifest.json \
  --key-id bky_... --key-ref env:BEDROCK_SIGNING_KEY --out sig.json --json

# Assemble and verify a complete signed bundle
bedrock charter bundle charter.yaml --manifest manifest.json \
  --signature sig1.json --signature sig2.json --root trust.json --out bundle.json --json
bedrock charter verify bundle.json --root trust.json --json

# Publish (registry) and activate an exact pin (gateway)
bedrock charter publish bundle.json --request-id brq_... --json
bedrock pin activate update.json --json

# Evaluate and dispatch through the gateway
bedrock gateway check request.json --json
bedrock gateway call request.json --json

# Export audit evidence and verify it offline
bedrock audit export --through-seq 42 --out evidence.json --json
bedrock audit verify evidence.json --root trust.json --replay --json
```

Run `bedrock --help` for the full 23-command inventory. `--json` emits one canonical (RFC 8785) JSON object plus LF on stdout and is required for automation; human output is not a parsing interface.

## What Bedrock is not

No amendment ceremony service, vote scheduling, governance token, precedent-as-law, binding dispute resolution, regex/LLM policy language, approval queue, or remote policy callback. An advisory dispute cites immutable evidence and can never alter evaluation. N-of-M means a static set of eligible Ed25519 keys authorizing one signed PR artifact — it proves control of configured keys, not independent humans or legitimacy. Fleet status reports software freshness only; a heartbeat is not hardware attestation.

## Architecture

The reference deployment is a Cloudflare Worker front end plus one SQLite-backed `BedrockTenantDO` per tenant. The worker performs bounded parsing and authentication; the Durable Object owns publication order, the active pin, pause state, instance observations, idempotency records, dispatch markers, and the audit sequence behind a single serialization gate. `bedrock serve --local` runs the same route handlers in a local emulator for development; it is not a production durability claim.

## Conformance

The numbered vectors TV-B--01..55 are implemented as executable tests in both language suites where applicable (`tests/conformance.test.ts`, `py/tests/test_conformance.py`), driven from the shared corpus in `conformance/`. Run `npm test` and `pytest py/tests -q`.

## License

MIT — see [LICENSE](LICENSE).
