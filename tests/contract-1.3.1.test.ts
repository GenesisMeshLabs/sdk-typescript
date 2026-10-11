/**
 * The 1.3.1 contract for SDKs, where the conformance vectors do not reach.
 * Each expected reason was checked against the Python reference's verifier
 * over the same export lines.
 */
import { describe, expect, it } from '@jest/globals';
import {
  BadRequestError, StrictJsonError, canonicalJson, checkpointCanonical, classifySubmissionError, decisionCanonical,
  entryDigest, executionCanonical, justificationCanonical, parseExportLines, parseJson, payloadDigest,
  seedSigner, signCanonical, verifyAttestationSignature, verifyEvidenceEvents, verifyRevocationFeedSignature,
  PERMANENT_REFUSALS, RECORD_PERMANENT_REFUSALS,
} from '../src/index.js';
import type {
  BoundaryDecision, DecisionJustification, EvidenceEvent, ExecutionEvidence, MembershipAttestation,
  RetentionCheckpoint, SovereignRevocationFeed,
} from '../src/index.js';
import { TEST_KEY } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'test');
const opts = {
  naPublicKeys: [v.na_public_key, TEST_KEY.pubBase64],
  executorKeys: [...v.executor_keys, { key_id: 'test', executor_sovereign_id: 'secrets-controller', public_key: TEST_KEY.pubBase64 }],
};
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
const payload = <T>(events: EvidenceEvent[], kind: string) => events.find(e => e.entry.entry_kind === kind)!.payload as unknown as T;
const reasons = (events: EvidenceEvent[]) =>
  [...new Set(verifyEvidenceEvents(relink(events), opts).failures.map(f => `${f.store_sequence}:${f.reason}`))].sort();

describe('a field the reference always writes as null, left out, gets the reference\'s reason', () => {
  it.each([
    ['execution outcome_detail', 'outcome_detail'],
    ['execution prev_evidence_digest', 'prev_evidence_digest'],
  ] as const)('%s: non_canonical_form signed as received, invalid_signature signed with null', async (_, field) => {
    const asReceived = parseExportLines(v.export);
    const record = payload<ExecutionEvidence>(asReceived, 'execution') as unknown as Record<string, unknown>;
    delete record[field];
    record['signature'] = await signCanonical(executionCanonical(record as unknown as ExecutionEvidence), signer);
    // Its digest changed, so the next record of the resource no longer links to it (as in the reference).
    expect(reasons(asReceived)).toEqual(['3:non_canonical_form', '6:resource_chain_break']);

    const withNull = parseExportLines(v.export);
    const other = payload<ExecutionEvidence>(withNull, 'execution') as unknown as Record<string, unknown>;
    other[field] = null;
    other['signature'] = await signCanonical(executionCanonical(other as unknown as ExecutionEvidence), signer);
    delete other[field];
    expect(reasons(withNull)).toContain('3:invalid_signature');
    expect(reasons(withNull)).not.toContain('3:payload_invalid');
  });
  it('justification trace.short_circuited_at', async () => {
    const events = parseExportLines(v.export);
    const proof = payload<DecisionJustification>(events, 'justification');
    delete (proof.trace as unknown as Record<string, unknown>)['short_circuited_at'];
    proof.signature = await signCanonical(justificationCanonical(proof), signer);
    expect(reasons(events)).toEqual(['2:non_canonical_form']);
  });
  it('the decision\'s binding fields', async () => {
    for (const drop of [
      (d: BoundaryDecision) => { delete (d.policy_binding as unknown as Record<string, unknown>)['resolution_failure']; },
      (d: BoundaryDecision) => { delete (d.attestation_binding as unknown as Record<string, unknown>)['subject_id']; },
    ]) {
      const events = parseExportLines(v.export);
      const decision = payload<{ decision: BoundaryDecision }>(events, 'decision').decision;
      drop(decision);
      decision.signature = await signCanonical(decisionCanonical(decision), signer);
      expect(reasons(events)).toEqual(['1:non_canonical_form']);
    }
  });
  it('a checkpoint\'s previous_checkpoint_id', async () => {
    const events = parseExportLines(v.export);
    const checkpoint = {
      ...v.checkpoint, resource_heads: {}, removed_through_sequence: 1, removed_count: 1, last_removed_entry_digest: 'x',
    } as Partial<RetentionCheckpoint>;
    delete checkpoint.previous_checkpoint_id;
    checkpoint.signature = await signCanonical(checkpointCanonical(checkpoint as RetentionCheckpoint), signer);
    events.push({
      ...events[0]!, payload: checkpoint as unknown as Record<string, unknown>,
      entry: {
        ...events[0]!.entry, entry_kind: 'retention_checkpoint', store_sequence: events.length + 1, decision_id: null,
        context_id: null, vendor_id: null, attestation_id: null, capability: null, outcome: null,
      },
    });
    expect(reasons(events)).toEqual([`${events.length}:non_canonical_form`]);
  });
});

describe('an envelope integer written as a float is refused, as the reference refuses it', () => {
  const line = v.export.trim().split('\n')[0]!;
  it.each([
    ['schema_version 1.0', '"schema_version":1', '"schema_version":1.0'],
    ['store_sequence 1.0', '"store_sequence":1,', '"store_sequence":1.0,'],
    ['store_sequence 1e0', '"store_sequence":1,', '"store_sequence":1e0,'],
  ])('%s', (_, from, to) => {
    const changed = line.replace(from, to);
    expect(changed).not.toBe(line);
    expect(() => parseExportLines(changed)).toThrow('envelope');
    const event = parseJson(changed) as EvidenceEvent;
    expect(verifyEvidenceEvents([event], opts).failures).toEqual([
      { store_sequence: null, reason: 'payload_invalid', detail: 'event envelope' },
    ]);
  });
  it('still reads the integers themselves', () => {
    expect(parseExportLines(line)).toHaveLength(1);
  });
});

describe('invalid_json is final only as the NA\'s answer', () => {
  it('a JSON fault in what the SDK read back stays retryable', () => {
    for (const reason of ['invalid_json', 'duplicate_key'] as const) {
      const unread = new StrictJsonError(reason, 'in the NA\'s response');
      expect(classifySubmissionError(unread).transient).toBe(true);
      expect(classifySubmissionError(unread, RECORD_PERMANENT_REFUSALS).transient).toBe(true);
    }
    const refused = new BadRequestError('request body is not accepted JSON (lone_surrogate)', 'invalid_json');
    expect(PERMANENT_REFUSALS.has('invalid_json')).toBe(true);
    expect(classifySubmissionError(refused).transient).toBe(false);
  });
});

describe('signatures that are not a list hold no signature', () => {
  it('for attestations and revocation feeds too', () => {
    const attestation = { ...v.attestation, signatures: { key_id: 'k', sig: 'AAAA' } } as unknown as MembershipAttestation;
    expect(verifyAttestationSignature(attestation, [TEST_KEY.pubBase64])).toBe(false);
    const feed = { feed_id: 'f', signatures: [null, 'x'] } as unknown as SovereignRevocationFeed;
    expect(verifyRevocationFeedSignature(feed, [TEST_KEY.pubBase64])).toBe(false);
  });
});

describe('the number grammar reads a token whole', () => {
  it.each([
    ['[-0.]', 'invalid_json'], ['[1e]', 'invalid_json'], ['[1E+]', 'invalid_json'], ['[-01]', 'negative_zero'],
    ['[1e400.]', 'non_finite_number'], ['[00]', 'invalid_json'], ['[-]', 'invalid_json'],
    [`[${'9'.repeat(21)}]`, 'integer_out_of_range'], ['[18446744073709551616]', 'integer_out_of_range'],
  ])('%s is refused as %s', (text, reason) => {
    expect(() => parseJson(text)).toThrow(expect.objectContaining({ reason }));
  });
  it.each(['[-0.0]', '[0e0]', '[1.5E-3]', '[18446744073709551615]', '[-9223372036854775808]'])('%s is read', text => {
    expect(() => parseJson(text)).not.toThrow();
    expect(canonicalJson(parseJson(text))).toBeDefined();
  });
});
