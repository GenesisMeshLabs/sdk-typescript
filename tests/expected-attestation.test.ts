import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseJson, verifyBoundaryDecision } from '../src/index.js';
import type { BoundaryDecision, VerifyDecisionOptions } from '../src/index.js';

/**
 * 1.9.2: verifyBoundaryDecision checks an expected attestation ID or subject
 * ID without the attestation itself. The decisions are the reference's
 * interop vectors: bd-003 is bound to an attestation, bd-001 to none.
 */
interface Vector { id: string; input: Record<string, unknown> }

const raw = readFileSync(fileURLToPath(new URL('./fixtures/conformance/interop.json', import.meta.url)), 'utf-8');
const suite = parseJson(raw) as { vectors: Vector[] };

function vector(id: string): { decision: BoundaryDecision; options: VerifyDecisionOptions } {
  const v = suite.vectors.find(x => x.id === id);
  if (!v) throw new Error(`no vector ${id}`);
  return {
    decision: v.input['decision'] as BoundaryDecision,
    options: { operatorPublicKeys: v.input['operator_public_keys'] as string[], now: new Date(v.input['now'] as string) },
  };
}

const ATTESTATION = '00000000-0000-4000-8000-000000000003';
const SUBJECT = 'sovereign-b';

describe('expected attestation and subject IDs (1.9.2)', () => {
  const { decision, options } = vector('bd-003');

  it.each([
    ['neither set', {}, true, 'authorized'],
    ['both match', { expectedAttestationId: ATTESTATION, expectedSubjectId: SUBJECT }, true, 'authorized'],
    ['attestation matches', { expectedAttestationId: ATTESTATION }, true, 'authorized'],
    ['subject matches', { expectedSubjectId: SUBJECT }, true, 'authorized'],
    ['another attestation', { expectedAttestationId: '00000000-0000-4000-8000-000000000099' }, false, 'attestation_binding_mismatch'],
    ['another subject', { expectedSubjectId: 'sovereign-c' }, false, 'attestation_binding_mismatch'],
    ['attestation matches, subject does not', { expectedAttestationId: ATTESTATION, expectedSubjectId: 'sovereign-c' }, false,
      'attestation_binding_mismatch'],
  ] as const)('%s', (_name, expected, accepted, reason) => {
    const r = verifyBoundaryDecision(decision, { ...options, ...expected });
    expect({ accepted: r.accepted, reason: r.reason }).toEqual({ accepted, reason });
  });

  it('requires an attestation binding when an expectation is given', () => {
    const unbound = vector('bd-001');
    expect(verifyBoundaryDecision(unbound.decision, unbound.options).accepted).toBe(true);
    for (const expected of [{ expectedAttestationId: 'a' }, { expectedSubjectId: SUBJECT }]) {
      const r = verifyBoundaryDecision(unbound.decision, { ...unbound.options, ...expected });
      expect({ accepted: r.accepted, reason: r.reason }).toEqual({ accepted: false, reason: 'attestation_binding_missing' });
    }
  });
});
