import { describe, expect, it } from '@jest/globals';
import {
  verifyBoundaryDecision, verifyEvidenceEvents, verifyRevocationFeedSignature,
  decisionCanonical, executionCanonical, checkpointCanonical, revocationFeedCanonical,
  entryDigest, payloadDigest, parseExportLines, signCanonical, seedSigner,
} from '../src/index.js';
import { freshnessProofCanonical } from '../src/canonical.js';
import type { BoundaryDecision, EvidenceEvent, ExecutionEvidence, SovereignRevocationFeed } from '../src/types.js';
import { TEST_KEY } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'test');
const options = { operatorPublicKeys: [TEST_KEY.pubBase64], now: new Date(v.allowed.decision.decision_made_at) };
async function signed(decision: BoundaryDecision) {
  decision.signature = await signCanonical(decisionCanonical(decision), signer); return decision;
}
function relink(events: EvidenceEvent[]): EvidenceEvent[] {
  let previous: string | null = null;
  for (const event of events) {
    event.entry.prev_entry_digest = previous;
    event.entry.payload_digest = payloadDigest(event.payload);
    event.entry_digest = entryDigest(event.entry);
    previous = event.entry_digest;
  }
  return events;
}

describe('boundary verifier negative paths', () => {
  it.each([
    ['unauthorized_attestation_basis', 'attestation_status', 'revoked'],
    ['unauthorized_capability_out_of_scope', 'capability_check', 'capability unavailable'],
    ['unauthorized_outside_validity_window', 'validity_window', 'outside validity'],
    ['unauthorized_insufficient_freshness', 'freshness_check', 'freshness failed'],
    ['unauthorized_gate_failure', 'other', 'denied'],
  ])('recognizes signed %s', async (reason, gate, denial) => {
    const decision = await signed({ ...v.allowed.decision, authorized: false, policy_binding: null,
      denial_reason: denial, gate_results: [{ gate_name: gate, passed: false, detail: denial }] });
    expect(verifyBoundaryDecision(decision, options)).toMatchObject({ accepted: true, authorized: false, reason });
  });
  it('recognizes failed policy resolution', async () => {
    const decision = await signed({ ...v.allowed.decision, authorized: false,
      gate_results: [], policy_binding: { ...v.allowed.decision.policy_binding!, resolution_status: 'failed' } });
    expect(verifyBoundaryDecision(decision, options).reason).toBe('unauthorized_policy_resolution_failed');
  });
  it('requires expected bindings to be present', async () => {
    const decision = await signed({ ...v.allowed.decision, policy_binding: null, attestation_binding: null });
    expect(verifyBoundaryDecision(decision, { ...options, expectedPolicies: [] }).reason).toBe('policy_binding_missing');
    expect(verifyBoundaryDecision(decision, { ...options, expectedAttestation: v.attestation }).reason).toBe('attestation_binding_missing');
  });
  it('checks freshness proof signatures and validity', async () => {
    const proof = { proof_id: 'proof', feed_sovereign_id: 'issuer', feed_sequence: 1, feed_digest: 'digest',
      attested_at: v.allowed.decision.decision_made_at, proof_valid_until: v.allowed.decision.decision_valid_until,
      issuer_sovereign_id: 'issuer', signature: null as BoundaryDecision['signature'] };
    proof.signature = await signCanonical(freshnessProofCanonical(proof), signer);
    let decision = await signed({ ...v.allowed.decision, freshness_proof: proof });
    const opts = { ...options, freshnessProofIssuerKeys: [TEST_KEY.pubBase64] };
    expect(verifyBoundaryDecision(decision, opts).accepted).toBe(true);
    proof.signature = { key_id: 'x', sig: 'bad' };
    decision = await signed({ ...decision, freshness_proof: proof });
    expect(verifyBoundaryDecision(decision, opts).reason).toBe('freshness_proof_invalid_signature');
    proof.proof_valid_until = '2000-01-01T00:00:00Z';
    proof.signature = await signCanonical(freshnessProofCanonical(proof), signer);
    decision = await signed({ ...decision, freshness_proof: proof });
    expect(verifyBoundaryDecision(decision, opts).reason).toBe('freshness_proof_expired');
  });
  it('verifies revocation feed signatures and rejects a changed feed', async () => {
    const feed: SovereignRevocationFeed = { feed_id: 'feed', issuer_sovereign_id: 'issuer', sequence: 1,
      issued_at: '2026-10-01T00:00:00Z', revoked_attestation_ids: ['a'], revocation_reasons: { a: 'done' }, issued_by: 'test', signatures: [] };
    feed.signatures.push(await signCanonical(revocationFeedCanonical(feed), signer));
    expect(verifyRevocationFeedSignature(feed, [TEST_KEY.pubBase64])).toBe(true);
    expect(verifyRevocationFeedSignature({ ...feed, sequence: 2 }, [TEST_KEY.pubBase64])).toBe(false);
  });
});

describe('evidence verifier negative paths', () => {
  const opts = { naPublicKeys: [v.na_public_key, TEST_KEY.pubBase64], executorKeys: [...v.executor_keys,
    { key_id: 'test', executor_sovereign_id: 'secrets-controller', public_key: TEST_KEY.pubBase64 }] };
  it.each(['denied', 'window', 'capability', 'decision chain', 'resource chain'])('rejects %s even with valid signatures and envelope digests', async mode => {
    const events = parseExportLines(v.export);
    const execution = events.find(e => e.entry.entry_kind === 'execution')!;
    const record = execution.payload as unknown as ExecutionEvidence;
    if (mode === 'denied') {
      const event = events.find(e => e.entry.entry_kind === 'decision' && e.entry.decision_id === record.decision_id)!;
      const decision = event.payload.decision as BoundaryDecision;
      decision.authorized = false; await signed(decision);
    }
    if (mode === 'window') record.executed_at = '2000-01-01T00:00:00Z';
    if (mode === 'capability') record.executed_capability = 'different';
    if (mode === 'decision chain') record.sequence_no = 3;
    if (mode === 'resource chain') record.prev_resource_digest = 'different';
    record.signature = await signCanonical(executionCanonical(record), signer);
    const failures = verifyEvidenceEvents(relink(events), opts).failures.map(f => f.reason);
    const expected: Record<string, string> = { denied: 'evidence_decision_denied', window: 'evidence_outside_decision_window', capability: 'evidence_capability_mismatch', 'decision chain': 'evidence_chain_break', 'resource chain': 'resource_chain_break' };
    expect(failures).toContain(expected[mode]);
    expect(failures).not.toContain('invalid_signature');
  });
  it('rejects malformed context and justification fields', () => {
    const events = parseExportLines(v.export);
    (events[0].payload.context as Record<string, unknown>).requested_at = 'invalid';
    events[1].payload.trace = null;
    expect(verifyEvidenceEvents(relink(events), opts).failures.filter(f => f.reason === 'payload_invalid')).toHaveLength(2);
  });
  it('verifies checkpoint events and their continuation links', async () => {
    const checkpoint = { ...v.checkpoint, resource_heads: {}, removed_through_sequence: 0, last_removed_entry_digest: 'anchor' };
    checkpoint.signature = await signCanonical(checkpointCanonical(checkpoint), signer);
    const event = parseExportLines(v.export)[0];
    event.entry.prev_entry_digest = 'anchor'; event.entry_digest = entryDigest(event.entry);
    expect(verifyEvidenceEvents([event], { ...opts, checkpoint }).verified).toBe(true);
    event.entry.prev_entry_digest = 'wrong'; event.entry_digest = entryDigest(event.entry);
    expect(verifyEvidenceEvents([event], { ...opts, checkpoint }).failures.map(f => f.reason)).toContain('store_chain_break');
    const cpEvent: EvidenceEvent = { ...event, payload: checkpoint as unknown as Record<string, unknown>, entry: { ...event.entry, entry_kind: 'retention_checkpoint' } };
    expect(verifyEvidenceEvents(relink([cpEvent]), opts).verified).toBe(true);
    checkpoint.signature = null;
    expect(verifyEvidenceEvents(relink([cpEvent]), opts).failures.map(f => f.reason)).toContain('invalid_signature');
    cpEvent.payload.removed_count = -1;
    expect(verifyEvidenceEvents(relink([cpEvent]), opts).failures.map(f => f.reason)).toContain('payload_invalid');
  });
});

it('returns a failure for null decisions supplied by untyped callers', () => {
  expect(verifyBoundaryDecision(null as unknown as BoundaryDecision, options)).toMatchObject({ accepted: false, reason: 'payload_invalid', decision_id: null });
});
