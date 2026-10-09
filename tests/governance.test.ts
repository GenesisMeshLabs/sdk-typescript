import { afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  GenesisMeshClient, ExecutionRecorder, seedSigner, signCanonical, decisionCanonical, pythonTimestamp,
  governedAction, DecisionVerificationError, GovernedActionError, summarizeDecision, reconcileResources, parseExportLines,
} from '../src/index.js';
import type { GovernedActionParams, ResourceState } from '../src/index.js';
import { TEST_KEY, mockFetch } from './helpers.js';
import { vectors } from './vectors.js';

function storedEntry() {
  const event = parseExportLines(vectors().export)[0]!;
  return { entry: event.entry, entry_digest: event.entry_digest };
}

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'test');
afterEach(() => { jest.useRealTimers(); });
async function setup(denied = false) {
  const evaluation = structuredClone(denied ? v.denied : v.allowed);
  // Timestamps in canonical form, as the NA writes them (v1.2.0).
  evaluation.decision.decision_made_at = pythonTimestamp(new Date(Date.now() - 1000));
  evaluation.decision.decision_valid_until = pythonTimestamp(new Date(Date.now() + 60_000));
  evaluation.decision.signature = await signCanonical(decisionCanonical(evaluation.decision), signer);
  const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://unused', fetch: mockFetch({ status: 500, body: {} }) as unknown as typeof fetch });
  const evaluate = jest.spyOn(gm.boundary, 'evaluate').mockResolvedValue(evaluation);
  const head = jest.spyOn(gm.evidenceStore, 'resourceHead').mockResolvedValue(null);
  const submit = jest.spyOn(gm.evidenceStore, 'submit').mockResolvedValue({ status: 'recorded', ...storedEntry() });
  const recorder = new ExecutionRecorder({ executorSovereignId: 'executor', signer });
  const params: GovernedActionParams = {
    attestation_id: v.attestation.attestation_id, requested_capability: 'sp-secret.rotate',
    resource_id: 'kv:v/s', resource_action: 'rotate', context: { context_id: evaluation.decision.context_id },
    verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [v.policy], expectedAttestation: v.attestation },
  };
  const action = jest.fn(async () => ({ value: 'returned only', execution_parameters: { secret_version: 'v2' } }));
  return { gm, recorder, params, action, evaluate, evaluation, head, submit };
}

describe('governedAction', () => {
  it('verifies ALLOW, reads the head and records the action result', async () => {
    const x = await setup();
    x.head.mockResolvedValue({ resource_sequence: 3, record_digest: 'prior' });
    const result = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(result).toMatchObject({ authorized: true, value: 'returned only', evidence: { resource_sequence: 4, prev_resource_digest: 'prior', execution_parameters: { secret_version: 'v2' } } });
    expect(result.evidence).not.toHaveProperty('value');
    expect(x.submit).toHaveBeenCalledTimes(1);
  });
  it('returns a verified DENY without action, head lookup or evidence', async () => {
    const x = await setup(true);
    expect(await governedAction(x.gm, x.recorder, x.params, x.action)).toMatchObject({ authorized: false });
    expect(x.action).not.toHaveBeenCalled();
    expect(x.head).not.toHaveBeenCalled();
    expect(x.submit).not.toHaveBeenCalled();
  });
  it('requires verification options at runtime even for JavaScript callers', async () => {
    const x = await setup();
    const params = { ...x.params, verify: undefined } as unknown as GovernedActionParams;
    await expect(governedAction(x.gm, x.recorder, params, x.action)).rejects.toBeInstanceOf(DecisionVerificationError);
    expect(x.evaluate).not.toHaveBeenCalled();
    expect(x.action).not.toHaveBeenCalled();
  });
  it.each(['unsigned', 'expired', 'tampered', 'wrong attestation', 'wrong policies'])('blocks %s ALLOW', async mode => {
    const x = await setup();
    if (mode === 'unsigned') x.evaluation.decision.signature = null;
    if (mode === 'expired') x.evaluation.decision.decision_valid_until = '2000-01-01T00:00:00Z';
    if (mode === 'tampered') x.evaluation.decision.context_id = 'changed';
    if (mode === 'wrong attestation') x.params.attestation_id = 'different';
    if (mode === 'wrong policies') x.params.verify.expectedPolicies = [];
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toBeInstanceOf(DecisionVerificationError);
    expect(x.action).not.toHaveBeenCalled();
  });
  it('rechecks expiry after history lookup', async () => {
    jest.useFakeTimers();
    const x = await setup();
    x.head.mockImplementation(async () => { jest.setSystemTime(Date.now() + 120_000); return null; });
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toMatchObject({ code: 'decision_expired' });
    expect(x.action).not.toHaveBeenCalled();
  });
  it('uses an explicit resource head and accepts duplicate submission', async () => {
    const x = await setup();
    x.submit.mockResolvedValue({ status: 'duplicate', ...storedEntry() });
    expect(await governedAction(x.gm, x.recorder, { ...x.params, prior_resource: null }, x.action))
      .toMatchObject({ submission: { status: 'duplicate' } });
    expect(x.head).not.toHaveBeenCalled();
  });
  it('records action failure without copying error text or name', async () => {
    const x = await setup();
    const failure = new Error('secret-value'); failure.name = 'secret-value';
    await expect(governedAction(x.gm, x.recorder, x.params, async () => { throw failure; })).rejects.toBe(failure);
    expect(x.submit.mock.calls[0][0]).toMatchObject({ outcome: 'failure', outcome_detail: 'action failed' });
  });
  it('preserves both errors when failure evidence cannot be submitted', async () => {
    const x = await setup();
    const failure = new Error('action'); const evidenceError = new Error('offline');
    x.submit.mockRejectedValue(evidenceError);
    const pending = governedAction(x.gm, x.recorder, x.params, async () => { throw failure; });
    await expect(pending).rejects.toBeInstanceOf(GovernedActionError);
    await expect(pending).rejects.toMatchObject({ cause: failure, evidenceError });
  });
  it('does not execute twice when submission fails', async () => {
    const x = await setup(); x.submit.mockRejectedValue(new Error('offline'));
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toThrow('offline');
    expect(x.action).toHaveBeenCalledTimes(1);
  });
  it('summarizes observe and enforce failures separately', () => {
    const summary = summarizeDecision(v.denied.decision);
    expect(summary.observed_failures).toHaveLength(1);
    expect(summary.enforced_failures).toHaveLength(2);
    expect(summary.applied_policies).toEqual(['vendor-sp-secret@1']);
  });
});

function state(id: string, action: string | null = 'create'): ResourceState {
  return { resource_id: id, resource_sequence: 1, record_digest: 'digest', last_action: action,
    last_outcome: 'success', last_success_action: action, last_success_parameters: { secret_version: 'v1' },
    last_executed_at: '2026-10-01T00:00:00Z', last_decision_id: 'decision' };
}
describe('reconcileResources', () => {
  it('classifies unmanaged, drifted, revoked, missing and matching resources', () => {
    const states = new Map(['drift', 'revoked', 'missing', 'match', 'failed'].map(id => [id, state(id, id === 'revoked' ? 'revoke' : id === 'failed' ? null : 'create')]));
    const findings = reconcileResources([
      { resource_id: 'new', exists: true }, { resource_id: 'drift', exists: true, version: 'v2' },
      { resource_id: 'revoked', exists: true }, { resource_id: 'missing', exists: false },
      { resource_id: 'match', exists: true, version: 'v1' }, { resource_id: 'failed', exists: true },
    ], states);
    expect(findings.map(f => f.status)).toEqual(['unmanaged', 'drifted', 'present_after_revoke', 'missing', 'in_sync', 'unmanaged']);
  });
  it('only infers missing resources for a complete, scoped inventory', () => {
    const states = new Map(['kv:a', 'other:b'].map(id => [id, state(id)]));
    expect(reconcileResources([], states)).toEqual([]);
    expect(reconcileResources([], states, { completeInventory: true, scopePrefix: 'kv:' }).map(f => f.resource_id)).toEqual(['kv:a']);
  });
  it('supports custom version fields and absence after deletion', () => {
    const deleted = state('deleted', 'delete');
    expect(reconcileResources([{ resource_id: 'deleted', exists: false }], new Map([['deleted', deleted]]))[0].status).toBe('in_sync');
    const custom = { ...state('custom'), last_success_parameters: { revision: 2 } };
    expect(reconcileResources([{ resource_id: 'custom', exists: true, version: '3' }], new Map([['custom', custom]]), { versionKey: 'revision' })[0].status).toBe('drifted');
  });
});

describe('governed-action binding requirements', () => {
  it('rejects missing policy expectations and missing attestation expectations', async () => {
    for (const field of ['expectedPolicies', 'expectedAttestation'] as const) {
      const x = await setup();
      const verify = { ...x.params.verify, [field]: undefined };
      await expect(governedAction(x.gm, x.recorder, { ...x.params, verify } as unknown as GovernedActionParams, x.action)).rejects.toBeInstanceOf(DecisionVerificationError);
      expect(x.action).not.toHaveBeenCalled();
    }
  });
  it('rejects a correctly signed response to another context', async () => {
    const x = await setup();
    x.params.context = { context_id: 'different-context' };
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toMatchObject({ code: 'context_binding_mismatch' });
    expect(x.action).not.toHaveBeenCalled();
  });
  it('generates a request context ID when the caller omits it', async () => {
    const x = await setup(); delete x.params.context;
    x.evaluate.mockImplementation(async request => {
      x.evaluation.decision.context_id = request.context!.context_id!;
      x.evaluation.decision.signature = await signCanonical(decisionCanonical(x.evaluation.decision), signer);
      return x.evaluation;
    });
    await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(x.evaluate.mock.calls[0][0].context?.context_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(x.action).toHaveBeenCalledTimes(1);
  });
  it('rejects an incomplete resource pair before evaluating', async () => {
    const x = await setup(); delete x.params.resource_action;
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toThrow('go together');
    expect(x.evaluate).not.toHaveBeenCalled();
  });
});
