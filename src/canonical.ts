/**
 * Canonical signed bodies and digests of GM protocol models, derived from
 * their wire JSON exactly as the Python models' to_canonical_json() and
 * digest() derive them. Pure functions; key operations live in auth.ts.
 */

import { canonicalDigest, canonicalJson } from './auth.js';
import type {
  AppliedPolicy,
  BoundaryDecision,
  BoundaryPolicy,
  DecisionJustification,
  EvidenceStoreEntry,
  ExecutionEvidence,
  MembershipAttestation,
  RetentionCheckpoint,
  SovereignRevocationFeed,
} from './types.js';

/** v0.59 resource-chain fields, omitted from the execution canonical form when absent. */
export const RESOURCE_CHAIN_FIELDS = [
  'resource_id',
  'resource_action',
  'resource_sequence',
  'prev_resource_digest',
] as const;

function without(model: object, always: readonly string[], whenNull: readonly string[] = []): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(model)) {
    if (always.includes(key)) continue;
    if (whenNull.includes(key) && (value === null || value === undefined)) continue;
    out[key] = value;
  }
  return out;
}

export function decisionCanonical(decision: BoundaryDecision): string {
  return canonicalJson(without(decision, ['signature'], ['policy_binding', 'attestation_binding']));
}

export function executionCanonical(evidence: ExecutionEvidence): string {
  return canonicalJson(without(evidence, ['signature'], RESOURCE_CHAIN_FIELDS));
}

/** `ExecutionEvidence.digest()`: links the per-decision and per-resource chains. */
export function executionDigest(evidence: ExecutionEvidence): string {
  return canonicalDigest(without(evidence, ['signature'], RESOURCE_CHAIN_FIELDS));
}

export function attestationCanonical(attestation: MembershipAttestation): string {
  return canonicalJson(without(attestation, ['signatures']));
}

/** `MembershipAttestation.digest()`: the value an AttestationBinding commits to. */
export function attestationDigest(attestation: MembershipAttestation): string {
  return canonicalDigest(without(attestation, ['signatures']));
}

export function revocationFeedCanonical(feed: SovereignRevocationFeed): string {
  return canonicalJson(without(feed, ['signatures']));
}

export function policyCanonical(policy: BoundaryPolicy): string {
  return canonicalJson(without(policy, ['signature']));
}

/** `BoundaryPolicy.digest()`. */
export function policyDigest(policy: BoundaryPolicy): string {
  return canonicalDigest(without(policy, ['signature']));
}

/** Digest of the ordered applied-policy list carried in a PolicyBinding. */
export function policySetDigest(policies: readonly Pick<AppliedPolicy, 'policy_id' | 'version' | 'policy_digest'>[]): string {
  return canonicalDigest(policies.map(p => [p.policy_id, p.version, p.policy_digest]));
}

export function justificationCanonical(proof: DecisionJustification): string {
  return canonicalJson(without(proof, ['signature']));
}

export function freshnessProofCanonical(proof: object): string {
  return canonicalJson(without(proof, ['signature']));
}

export function checkpointCanonical(checkpoint: RetentionCheckpoint): string {
  return canonicalJson(without(checkpoint, ['signature']));
}

/** `EvidenceStoreEntry.digest()`: every envelope field. */
export function entryDigest(entry: EvidenceStoreEntry): string {
  return canonicalDigest(entry);
}

/** SHA-256 of a stored payload's canonical JSON. */
export function payloadDigest(payload: unknown): string {
  return canonicalDigest(payload);
}
