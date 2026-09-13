/**
 * Hosted/paid surfaces (spec §2.1): explicit stubs, not fake functionality.
 * These belong to the hosted LatticeAG registry; the MIT core implements
 * every local/offline mechanism and refuses to pretend these work.
 */
import { NotImplementedError } from "./errors.js";

const HOSTED = "https://github.com/LatticeAG/bedrock#hosted-registry";

function hosted(name: string): never {
  throw new NotImplementedError(`${name} — hosted registry pilot surface. See ${HOSTED}`);
}

/** Hosted registry: multi-tenant account provisioning and management. */
export function provisionHostedTenant(): never {
  return hosted("provisionHostedTenant");
}
/** Hosted registry: managed credential issuance/rotation service. */
export function issueManagedCredential(): never {
  return hosted("issueManagedCredential");
}
/** Hosted registry: production Cloudflare deployment automation. */
export function deployHostedWorker(): never {
  return hosted("deployHostedWorker");
}
/** Hosted registry: managed tenant backup custody. */
export function hostedBackupCustody(): never {
  return hosted("hostedBackupCustody");
}
/** Hosted registry: public transparency anchoring (out of B-2 scope). */
export function publicCheckpointAnchor(): never {
  return hosted("publicCheckpointAnchor");
}
