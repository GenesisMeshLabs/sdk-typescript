/**
 * Canonical signed bodies and digests of GM protocol models, derived from
 * their wire JSON exactly as the Python models' to_canonical_json() and
 * digest() derive them. Pure functions; key operations live in auth.ts.
 */

import { canonicalDigest, canonicalJson, copyPythonFloats, defineMember } from './auth.js';
import type {
  AgreementRecord,
  AppliedPolicy,
  CapabilityCounter,
  DataAccessIntent,
  DataLicensePolicy,
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
    defineMember(out, key, value);
  }
  // The copy keeps the record's float spellings (`1000.0`), so it signs as received.
  copyPythonFloats(model, out);
  return out;
}

/** Decision fields omitted from the signed form when absent (checked against the field registry). */
export const DECISION_OMITTED_WHEN_ABSENT = ['policy_binding', 'attestation_binding'] as const;

export function decisionCanonical(decision: BoundaryDecision): string {
  return canonicalJson(without(decision, ['signature'], DECISION_OMITTED_WHEN_ABSENT));
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

/** Checkpoint fields omitted from the signed form when absent (v1.3.0; checked against the field registry). */
export const CHECKPOINT_OMITTED_WHEN_ABSENT = ['observation_heads'] as const;

export function checkpointCanonical(checkpoint: RetentionCheckpoint): string {
  return canonicalJson(without(checkpoint, ['signature'], CHECKPOINT_OMITTED_WHEN_ABSENT));
}

/** Envelope fields left out when absent (v1.3.0; checked against the field registry), so 1.2 digests hold. */
export const ENVELOPE_OMITTED_WHEN_ABSENT = ['record_id', 'subject_id', 'matched_evidence_id', 'observation_sequence'] as const;

/** `EvidenceStoreEntry.digest()`: every envelope field. */
export function entryDigest(entry: EvidenceStoreEntry): string {
  return canonicalDigest(without(entry, [], ENVELOPE_OMITTED_WHEN_ABSENT));
}

/** SHA-256 of a stored payload's canonical JSON. */
export function payloadDigest(payload: unknown): string {
  return canonicalDigest(payload);
}

/** Fields both parties sign; identical for CapabilityCounter and AgreementRecord (excludes ids and timestamps). */
export const AGREEMENT_CANONICAL_FIELDS = [
  'agreed_terms', 'graph_digest', 'offer_id', 'offerer_evidence',
  'offerer_sovereign_id', 'responder_evidence', 'responder_sovereign_id',
] as const;

/** The body both parties of an agreement sign. */
export function agreementCanonical(record: AgreementRecord | CapabilityCounter): string {
  const source = record as unknown as Record<string, unknown>;
  const body: Record<string, unknown> = {};
  for (const key of AGREEMENT_CANONICAL_FIELDS) body[key] = source[key] ?? null;
  return canonicalJson(body);
}

export function dataLicensePolicyCanonical(policy: DataLicensePolicy): string {
  return canonicalJson(without(policy, ['signature']));
}

export function dataAccessIntentCanonical(intent: DataAccessIntent): string {
  return canonicalJson(without(intent, ['signature']));
}
