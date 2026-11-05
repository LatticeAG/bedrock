import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { canonicalString } from "../src/canon.js";
import * as FX from "../src/fixtures.js";
import { makeConfig } from "./harness.js";

test("serve reports invalid response key format without revealing key material", () => {
  const dir = mkdtempSync(resolve(".bedrock-local-test-"));
  try {
    writeFileSync(`${dir}/trust.json`, canonicalString(FX.R));
    writeFileSync(`${dir}/config.yaml`, JSON.stringify(makeConfig()));
    for (const key of ["bad", `${Buffer.alloc(32, 7).toString("base64url")}=`, Buffer.alloc(31, 7).toString("base64url")]) {
      const result = spawnSync(process.execPath, ["dist/src/cli.js", "serve", "--local", "--config", `${dir}/config.yaml`, "--json"], {
        encoding: "utf8", env: { ...process.env, BEDROCK_AUTH_RECORDS: "[]", BEDROCK_RESPONSE_KEYS: JSON.stringify({ active_key_id: "rk1", keys: [{ key_id: "rk1", key_base64url: key }] }) },
      });
      assert.equal(result.status, 2);
      const error = JSON.parse(result.stdout).error;
      assert.equal(error.code, "SCHEMA");
      assert.match(error.message, /BEDROCK_RESPONSE_KEYS.*canonical unpadded base64url.*32 bytes/);
      assert.ok(!error.message.includes(key));
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
