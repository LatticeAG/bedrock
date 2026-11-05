#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npm run build
work=$(mktemp -d ./.bedrock-local-smoke-XXXXXX)
trap 'rm -rf "$work"' EXIT
node --input-type=module - "$work" <<'JS'
import { writeFileSync } from "node:fs";
import { canonicalString } from "./dist/src/canon.js";
import { B1, R } from "./dist/src/fixtures.js";
const dir = process.argv[2];
writeFileSync(`${dir}/bundle.json`, canonicalString(B1));
writeFileSync(`${dir}/trust.json`, canonicalString(R));
JS
node dist/src/cli.js charter verify "$work/bundle.json" --root "$work/trust.json" --json
