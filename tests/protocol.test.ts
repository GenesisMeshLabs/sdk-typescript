import { describe, expect, it } from '@jest/globals';
import {
  attestationDigest, policyDigest, executionDigest, entryDigest, payloadDigest,
  verifyAttestationSignature, verifyPolicySignature, verifyDecisionSignature, verifyJustificationSignature,
  verifyRetentionCheckpoint, verifyExecutionSignature, verifyEvidenceEvents, verifyBoundaryDecision,
  parseExportLines, parseTimestampMicros, canonicalJson, parseJson, pythonTimestamp,
} from '../src/index.js';
import type { EvidenceEvent } from '../src/types.js';
import { vectors } from './vectors.js';

const v = vectors();
const keys = [v.na_public_key];
const options = { naPublicKeys: keys, executorKeys: v.executor_keys };
const decisionOptions = {
  operatorPublicKeys: keys, now: new Date(v.allowed.decision.decision_made_at),
  expectedPolicies: [v.policy], expectedAttestation: v.attestation,
};

describe('Python canonical JSON', () => {
  it.each([
    ['non-ASCII', { owner: 'Zoë 😀' }, '{"owner":"Zo\\u00eb \\ud83d\\ude00"}'],
    ['code-point key ordering', { '\uE000': 1, '😀': 2 }, '{"\\ue000":1,"\\ud83d\\ude00":2}'],
    ['DEL', '\x7f', '"\\u007f"'],
    ['small float', 0.00001, '1e-05'],
    ['large float', 1e21, '1e+21'],
    ['fixed float', 0.0001, '0.0001'],
    ['nested ordering', { z: [{ b: 1, a: 2 }] }, '{"z":[{"a":2,"b":1}]}'],
  ])('%s', (_name, value, expected) => expect(canonicalJson(value)).toBe(expected));
  it('preserves integral float lexemes from the NA, including negative zero', () => {
    expect(canonicalJson(parseJson('{"x":90.0,"y":[-0.0,1e16]}')))
      .toBe('{"x":90.0,"y":[-0.0,1e+16]}');
  });
  it.each([Infinity, -Infinity, NaN])('rejects non-finite %s', value => expect(() => canonicalJson(value)).toThrow());
  it('formats Pydantic timestamps and retains microsecond differences', () => {
    expect(pythonTimestamp(new Date('2026-10-01T00:00:00.001Z'))).toBe('2026-10-01T00:00:00.001000Z');
    expect(pythonTimestamp(new Date('2026-10-01T00:00:00Z'))).toBe('2026-10-01T00:00:00Z');
    expect(parseTimestampMicros('2026-10-01T00:00:00.000002Z') - parseTimestampMicros('2026-10-01T00:00:00.000001Z')).toBe(1);
  });
  it.each(['bad', '2026-02-30T00:00:00Z', '2026-10-01T25:00:00Z'])('rejects invalid timestamp %s', value => {
    expect(() => parseTimestampMicros(value)).toThrow();
  });
});

describe('Python signed artifacts', () => {
  it('matches every reference digest', () => {
    expect(attestationDigest(v.attestation)).toBe(v.attestation_digest);
    expect(policyDigest(v.policy)).toBe(v.policy_digest);
    expect(v.executions.map(executionDigest)).toEqual(v.execution_digests);
  });
  it.each([
    ['attestation', () => verifyAttestationSignature(v.attestation, keys), () => verifyAttestationSignature({ ...v.attestation, subject_id: 'changed' }, keys)],
    ['policy', () => verifyPolicySignature(v.policy, keys), () => verifyPolicySignature({ ...v.policy, description: 'changed' }, keys)],
    ['decision', () => verifyDecisionSignature(v.allowed.decision, keys), () => verifyDecisionSignature({ ...v.allowed.decision, authorized: false }, keys)],
    ['justification', () => verifyJustificationSignature(v.allowed.justification_proof, keys), () => verifyJustificationSignature({ ...v.allowed.justification_proof, proof_id: 'changed' }, keys)],
    ['checkpoint', () => verifyRetentionCheckpoint(v.checkpoint, keys), () => verifyRetentionCheckpoint({ ...v.checkpoint, removed_count: 100 }, keys)],
    ['execution', () => verifyExecutionSignature(v.executions[0], v.executor_keys[0].public_key), () => verifyExecutionSignature({ ...v.executions[0], outcome: 'failure' }, v.executor_keys[0].public_key)],
  ])('verifies %s and rejects tampering', (_name, verify, tamper) => {
    expect(verify()).toBe(true);
    expect(tamper()).toBe(false);
  });
  it('verifies ALLOW and signed policy DENY with expected bindings', () => {
    expect(verifyBoundaryDecision(v.allowed.decision, decisionOptions)).toMatchObject({ accepted: true, authorized: true });
    expect(verifyBoundaryDecision(v.denied.decision, decisionOptions)).toMatchObject({ accepted: true, authorized: false, reason: 'unauthorized_policy_gate_failure' });
  });
  it.each([
    ['missing_signature', { ...v.allowed.decision, signature: null }, decisionOptions],
    ['decision_expired', v.allowed.decision, { ...decisionOptions, now: new Date('2100-01-01') }],
    ['invalid_signature', { ...v.allowed.decision, context_id: 'changed' }, decisionOptions],
    ['attestation_binding_mismatch', v.allowed.decision, { ...decisionOptions, expectedAttestation: { ...v.attestation, subject_id: 'changed' } }],
    ['policy_binding_mismatch', v.allowed.decision, { ...decisionOptions, expectedPolicies: [] }],
    ['payload_invalid', { ...v.allowed.decision, decision_valid_until: 'invalid' }, decisionOptions],
  ])('rejects %s', (reason, decision, opts) => expect(verifyBoundaryDecision(decision, opts)).toMatchObject({ accepted: false, reason }));
});

describe('offline evidence export', () => {
  it('verifies the complete Python export', () => {
    expect(verifyEvidenceEvents(parseExportLines(v.export), options)).toEqual({
      verified: true, checked_entries: 8, decisions: 3, executions: 2, failures: [],
    });
  });
  it('ignores blank lines', () => expect(parseExportLines('\n' + v.export + '\n')).toHaveLength(8));
  it.each(['null', '{}', '{"schema":"gm.evidence.event","schema_version":1}', '{"schema":"gm.evidence.event","schema_version":2}', 'invalid'])('rejects malformed export %s', text => {
    expect(() => parseExportLines(text)).toThrow();
  });
  it('returns a failure for a malformed event passed directly', () => {
    expect(verifyEvidenceEvents([{} as EvidenceEvent], options)).toMatchObject({ verified: false, failures: [{ reason: 'payload_invalid' }] });
  });
  it('rejects unknown executor keys', () => {
    expect(verifyEvidenceEvents(parseExportLines(v.export), { ...options, executorKeys: [] }).failures)
      .toEqual(expect.arrayContaining([expect.objectContaining({ reason: 'invalid_signature', detail: 'execution' })]));
  });
  it('detects a removed store entry and reordered entries', () => {
    const events = parseExportLines(v.export);
    for (const modified of [events.filter((_, i) => i !== 1), [...events].reverse()]) {
      expect(verifyEvidenceEvents(modified, options).failures).toEqual(expect.arrayContaining([expect.objectContaining({ reason: 'store_sequence_gap' })]));
    }
  });
  it('allows store gaps in filtered histories', () => {
    const events = parseExportLines(v.export).filter(e => e.entry.entry_kind === 'decision');
    expect(verifyEvidenceEvents(events, { ...options, contiguous: false }).verified).toBe(true);
  });
  it('detects a changed envelope, payload, and resource chain', () => {
    const events = parseExportLines(v.export);
    const ev = events.find(e => e.entry.entry_kind === 'execution')!;
    ev.payload.resource_sequence = 7;
    ev.entry.vendor_id = 'changed';
    const reasons = verifyEvidenceEvents(events, options).failures.map(f => f.reason);
    expect(reasons).toEqual(expect.arrayContaining(['entry_digest_mismatch', 'payload_digest_mismatch', 'invalid_signature', 'resource_chain_break']));
  });
  it.each(['executed_at', 'sequence_no', 'signature'])('rejects invalid execution field %s without throwing', field => {
    const events = parseExportLines(v.export);
    const ev = events.find(e => e.entry.entry_kind === 'execution')!;
    ev.payload[field] = field === 'sequence_no' ? -1 : 42;
    ev.entry.payload_digest = payloadDigest(ev.payload);
    ev.entry_digest = entryDigest(ev.entry);
    expect(verifyEvidenceEvents(events, options).failures).toEqual(expect.arrayContaining([expect.objectContaining({ reason: 'payload_invalid' })]));
  });
  it('does not trust an unsigned caller-supplied checkpoint', () => {
    expect(verifyEvidenceEvents([], { ...options, checkpoint: { ...v.checkpoint, signature: null } }).verified).toBe(false);
  });
});
