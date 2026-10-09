import { afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  GenesisMeshClient, ExecutionRecorder, seedSigner, signCanonical, decisionCanonical, executionDigest,
  governedAction, DecisionVerificationError, GovernedActionError, MetadataRefusedError, EvidenceNotKeptError,
  summarizeDecision, reconcileResources, parseExportLines, withoutRefusedMetadata,
  MemoryOutbox, NetworkError, ConflictError, RateLimitError, ServiceUnavailableError, SecretMaterialError,
  NotFoundError, ValidationError, ForbiddenError, PREDECESSOR_DEAD_LETTERED,
} from '../src/index.js';
import type { EvidenceOutbox, ExecutionEvidence, GovernedActionParams, ResourceState } from '../src/index.js';
import { TEST_KEY, mockFetch } from './helpers.js';
import { vectors } from './vectors.js';

function storedEntry() {
  const event = parseExportLines(vectors().export)[0]!;
  return { entry: event.entry, entry_digest: event.entry_digest };
}

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'test');
afterEach(() => { jest.useRealTimers(); });
async function setup(denied = false, outbox: EvidenceOutbox | null = null) {
  const evaluation = structuredClone(denied ? v.denied : v.allowed);
  evaluation.decision.decision_made_at = new Date(Date.now() - 1000).toISOString();
  evaluation.decision.decision_valid_until = new Date(Date.now() + 60_000).toISOString();
  evaluation.decision.signature = await signCanonical(decisionCanonical(evaluation.decision), signer);
  const gm = new GenesisMeshClient({
    audience: 'TEST', baseUrl: 'http://unused', fetch: mockFetch({ status: 500, body: {} }) as unknown as typeof fetch, outbox: outbox ?? undefined,
  });
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
  return { gm, recorder, params, action, evaluate, evaluation, head, submit, outbox: outbox! };
}
const withOutbox = (denied = false) => setup(denied, new MemoryOutbox());

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
    const error = await governedAction(x.gm, x.recorder, x.params, async () => { throw failure; }).catch(e => e);
    expect(error).toBeInstanceOf(GovernedActionError);
    expect(error).toMatchObject({ cause: failure, evidenceError, evidence: { outcome: 'failure' } });
  });
  it('does not execute twice when submission fails', async () => {
    const x = await setup(); x.submit.mockRejectedValue(new Error('offline'));
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toThrow('offline');
    expect(x.action).toHaveBeenCalledTimes(1);
  });
  it('refuses secret metadata before anything is signed, without an outbox', async () => {
    const x = await setup();
    const leaky = jest.fn(async () => ({ execution_parameters: { client_secret: 's3cr3t' } }));
    await expect(governedAction(x.gm, x.recorder, x.params, leaky)).rejects.toBeInstanceOf(SecretMaterialError);
    expect(x.submit).not.toHaveBeenCalled();
  });
  it('summarizes observe and enforce failures separately', () => {
    const summary = summarizeDecision(v.denied.decision);
    expect(summary.observed_failures).toHaveLength(1);
    expect(summary.enforced_failures).toHaveLength(2);
    expect(summary.applied_policies).toEqual(['vendor-sp-secret@1']);
  });
});

describe('governedAction with the evidence outbox (1.2.0)', () => {
  it('fails before evaluating when the outbox cannot be read', async () => {
    const x = await withOutbox();
    jest.spyOn(x.outbox, 'list').mockRejectedValue(new Error('outbox file 000000000001-a.json is unreadable'));
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toThrow('unreadable');
    expect(x.evaluate).not.toHaveBeenCalled();
    expect(x.action).not.toHaveBeenCalled();
  });
  it('removes the record once the NA admits it', async () => {
    const x = await withOutbox();
    const result = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(result.submission).toMatchObject({ status: 'recorded' });
    expect(result.queued).toBeUndefined();
    expect(await x.outbox.list()).toEqual([]);
  });
  it('returns the value with the record pending when the NA is unreachable, then admits it on flush', async () => {
    const x = await withOutbox();
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    const result = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(result).toMatchObject({ value: 'returned only', queued: { state: 'pending', attempts: 1, last_error: { status: 0, code: 'network_error' } } });
    expect(result.submission).toBeUndefined();
    const [kept] = await x.outbox.list();
    expect(kept!.evidence).toEqual(result.evidence);
    expect(Date.parse(kept!.next_attempt_at!)).toBeGreaterThan(Date.now());
    expect(await x.gm.evidenceStore.flushPending()).toMatchObject({ admitted: [], pending: [{ id: kept!.id }] });
    const flushed = await x.gm.evidenceStore.flushPending({ ignoreBackoff: true });
    expect(flushed.admitted.map(e => e.id)).toEqual([kept!.id]);
    expect(x.submit).toHaveBeenLastCalledWith(result.evidence!);
    expect(await x.outbox.list()).toEqual([]);
  });
  it.each([
    ['a 503', new ServiceUnavailableError()],
    ['a 429', new RateLimitError()],
    ['a disabled store', new NotFoundError('disabled', 'evidence_store_disabled')],
    ['an executor key not registered yet', new ValidationError('unknown', 'evidence_unknown_executor')],
    ['a gap behind a record not admitted yet', new ValidationError('gap', 'resource_chain_gap')],
    ['a proxy error page', new ForbiddenError('Forbidden', 'unknown')],
    ['an unknown error', new TypeError('fetch failed')],
  ])('keeps the record pending after %s', async (_, error) => {
    const x = await withOutbox();
    x.submit.mockRejectedValueOnce(error);
    expect((await governedAction(x.gm, x.recorder, x.params, x.action)).queued).toMatchObject({ state: 'pending' });
  });
  it('dead-letters a record the NA refuses, with its code, and keeps it', async () => {
    const x = await withOutbox();
    x.submit.mockRejectedValueOnce(new ConflictError('taken', 'evidence_conflict'));
    const result = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(result.queued).toMatchObject({ state: 'dead_letter', last_error: { status: 409, code: 'evidence_conflict' } });
    expect(await x.gm.evidenceStore.flushPending({ ignoreBackoff: true })).toEqual({ admitted: [], pending: [], dead_lettered: [] });
    expect(await x.outbox.list()).toMatchObject([{ state: 'dead_letter' }]);
    expect(x.submit).toHaveBeenCalledTimes(1);
  });
  it('chains a second action from the pending head and submits both, in order, with the second', async () => {
    const x = await withOutbox();
    x.head.mockResolvedValue({ resource_sequence: 3, record_digest: 'prior' });
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    const first = await governedAction(x.gm, x.recorder, x.params, x.action);
    const second = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(x.head).toHaveBeenCalledTimes(1);
    expect(second.evidence).toMatchObject({ resource_sequence: 5, prev_resource_digest: executionDigest(first.evidence!) });
    // The NA just answered the evaluation: the first record goes first, despite its backoff.
    expect(second.submission).toMatchObject({ status: 'recorded' });
    expect(x.submit.mock.calls.map(c => c[0])).toEqual([first.evidence, first.evidence, second.evidence]);
    expect(await x.outbox.list()).toEqual([]);
  });
  it('dead-letters a record whose predecessor is refused, without submitting it', async () => {
    const x = await withOutbox();
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    const first = await governedAction(x.gm, x.recorder, x.params, x.action);
    x.submit.mockRejectedValueOnce(new ConflictError('taken', 'evidence_conflict'));
    const second = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(second.queued).toMatchObject({ state: 'dead_letter', last_error: { code: PREDECESSOR_DEAD_LETTERED } });
    expect(x.submit).toHaveBeenCalledTimes(2);
    expect(x.submit).toHaveBeenLastCalledWith(first.evidence!);
    expect((await x.outbox.list()).map(e => e.state)).toEqual(['dead_letter', 'dead_letter']);
    // A third action no longer chains from the dead records.
    x.head.mockResolvedValue({ resource_sequence: 9, record_digest: 'na-head' });
    const third = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(third.evidence).toMatchObject({ resource_sequence: 10, prev_resource_digest: 'na-head' });
  });
  it('dead-letters a new record at once when its predecessor is already a dead letter', async () => {
    const x = await withOutbox();
    const signed = (prior?: ExecutionEvidence) => x.recorder.record({
      decision: x.evaluation.decision, executed_capability: 'sp-secret.rotate', outcome: 'success',
      resource_id: 'kv:v/s', resource_action: 'rotate', prior_resource: prior ?? null,
    });
    const a = await signed();
    x.submit.mockRejectedValueOnce(new ConflictError('taken', 'evidence_conflict'));
    expect((await x.gm.evidenceStore.enqueue(a)).queued).toMatchObject({ state: 'dead_letter' });
    const b = await signed(a);
    expect((await x.gm.evidenceStore.enqueue(b)).queued).toMatchObject({ state: 'dead_letter', last_error: { code: PREDECESSOR_DEAD_LETTERED } });
    expect(x.submit).toHaveBeenCalledTimes(1);
  });
  it('waits on the decision chain as on the resource chain', async () => {
    const x = await withOutbox();
    const a = await x.recorder.record({ decision: x.evaluation.decision, executed_capability: 'c', outcome: 'success' });
    const b = await x.recorder.record({ decision: x.evaluation.decision, executed_capability: 'c', outcome: 'success', prior_record: a });
    x.submit.mockRejectedValue(new NetworkError('offline'));
    await x.gm.evidenceStore.enqueue(a);
    expect((await x.gm.evidenceStore.enqueue(b)).queued).toMatchObject({ state: 'pending', attempts: 0 });
    // Inline, b waits behind a's failed retry.
    expect(x.submit.mock.calls.map(c => c[0])).toEqual([a, a]);
  });
  it('resubmits a record already in the outbox, and refuses another record with its id', async () => {
    const x = await withOutbox();
    const a = await x.recorder.record({ decision: x.evaluation.decision, executed_capability: 'c', outcome: 'success' });
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    await x.gm.evidenceStore.enqueue(a);
    expect((await x.gm.evidenceStore.enqueue(a)).submission).toMatchObject({ status: 'recorded' });
    const imposter = { ...a, outcome: 'failure' as const };
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    await x.gm.evidenceStore.enqueue(a);
    await expect(x.gm.evidenceStore.enqueue(imposter)).rejects.toThrow('different record');
  });
  it('reports an admitted record as admitted even when the outbox cannot remove it', async () => {
    const x = await withOutbox();
    jest.spyOn(x.outbox, 'remove').mockRejectedValueOnce(new Error('disk'));
    const result = await governedAction(x.gm, x.recorder, x.params, x.action);
    expect(result.submission).toMatchObject({ status: 'recorded' });
    // The leftover is resubmitted, found a duplicate and removed by the next flush.
    x.submit.mockResolvedValueOnce({ status: 'duplicate', ...storedEntry() });
    expect((await x.gm.evidenceStore.flushPending()).admitted).toHaveLength(1);
    expect(await x.outbox.list()).toEqual([]);
  });
  it('ends a flush at the first transient error and skips records in backoff', async () => {
    const x = await withOutbox();
    x.submit.mockRejectedValue(new NetworkError('offline'));
    await governedAction(x.gm, x.recorder, x.params, x.action);
    await governedAction(x.gm, x.recorder, { ...x.params, resource_id: 'kv:v/other' }, x.action);
    expect((await x.outbox.list()).map(e => e.attempts)).toEqual([1, 1]);
    x.submit.mockClear();
    const flushed = await x.gm.evidenceStore.flushPending({ ignoreBackoff: true });
    expect(x.submit).toHaveBeenCalledTimes(1);
    expect(flushed.pending.map(e => e.attempts)).toEqual([2, 1]);
    x.submit.mockClear();
    expect((await x.gm.evidenceStore.flushPending()).pending).toHaveLength(2);
    expect(x.submit).not.toHaveBeenCalled();
  });
  it('shares one run between concurrent flushes, and rejects rather than throws without an outbox', async () => {
    const x = await withOutbox();
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    await governedAction(x.gm, x.recorder, x.params, x.action);
    const [a, b] = [x.gm.evidenceStore.flushPending({ ignoreBackoff: true }), x.gm.evidenceStore.flushPending({ ignoreBackoff: true })];
    expect((await a).admitted).toHaveLength(1);
    expect(await b).toBe(await a);
    const bare = await setup();
    const pending = bare.gm.evidenceStore.flushPending();
    await expect(pending).rejects.toMatchObject({ code: 'outbox_required' });
  });
  it('reports a guard refusal after the action with the value and the recorded outcome', async () => {
    const x = await withOutbox();
    const leaky = jest.fn(async () => ({
      value: 'v', outcome_detail: 'rotated', execution_parameters: { client_secret: 's3cr3t', secret_version: 'v2' },
    }));
    const error = await governedAction(x.gm, x.recorder, x.params, leaky).catch(e => e);
    expect(error).toBeInstanceOf(MetadataRefusedError);
    expect(error).toMatchObject({
      code: 'governed_action_metadata_refused', value: 'v', dropped: ['client_secret'], submission: { status: 'recorded' },
      evidence: { outcome: 'success', execution_parameters: { secret_version: 'v2' }, outcome_detail: 'rotated [secret guard dropped: client_secret]' },
    });
    expect(error.cause).toBeInstanceOf(SecretMaterialError);
    expect(x.submit).toHaveBeenCalledWith(error.evidence);
    expect(JSON.stringify(error.evidence)).not.toContain('s3cr3t');
    expect(leaky).toHaveBeenCalledTimes(1);
  });
  it('keeps the value and the signed record when the outbox fails after the action', async () => {
    const x = await withOutbox();
    jest.spyOn(x.outbox, 'add').mockRejectedValue(new Error('disk full'));
    const error = await governedAction(x.gm, x.recorder, x.params, x.action).catch(e => e);
    expect(error).toBeInstanceOf(EvidenceNotKeptError);
    expect(error).toMatchObject({ code: 'governed_action_evidence_unkept', value: 'returned only', evidence: { outcome: 'success' } });
    expect(x.submit).not.toHaveBeenCalled();
  });
  it('keeps the failure record pending and rethrows when it cannot be submitted', async () => {
    const x = await withOutbox();
    const failure = new Error('action');
    x.submit.mockRejectedValue(new NetworkError('offline'));
    await expect(governedAction(x.gm, x.recorder, x.params, async () => { throw failure; })).rejects.toBe(failure);
    const [kept] = await x.outbox.list();
    expect(kept).toMatchObject({ state: 'pending', attempts: 1, evidence: { outcome: 'failure', outcome_detail: 'action failed' } });
  });
  it('lets an explicit prior resource override the pending head', async () => {
    const x = await withOutbox();
    x.submit.mockRejectedValueOnce(new NetworkError('offline'));
    await governedAction(x.gm, x.recorder, x.params, x.action);
    const second = await governedAction(x.gm, x.recorder, { ...x.params, prior_resource: null }, x.action);
    expect(second.evidence).toMatchObject({ resource_sequence: 1, prev_resource_digest: null });
  });
});

describe('withoutRefusedMetadata', () => {
  it('drops only the refused parameters and a refused detail', () => {
    expect(withoutRefusedMetadata({ password: 'x', version: 'v1', nested: { token: 'y' } }, '-----BEGIN KEY')).toEqual({
      execution_parameters: { version: 'v1' },
      outcome_detail: '[secret guard dropped: nested, outcome_detail, password]',
      dropped: ['nested', 'outcome_detail', 'password'],
    });
  });
  it('names only plain field names in the note', () => {
    expect(withoutRefusedMetadata({ 'a b': 'x'.repeat(130), [`${'y'.repeat(70)}`]: 'z'.repeat(130), ok: 1 }, null)).toMatchObject({
      execution_parameters: { ok: 1 }, outcome_detail: '[secret guard dropped: 2 other fields]',
    });
  });
  it('drops everything when the rest is still too large', () => {
    const big = Object.fromEntries(Array.from({ length: 4 }, (_, i) => [`k${i}`, 'x'.repeat(5000)]));
    expect(withoutRefusedMetadata(big, null)).toEqual({
      execution_parameters: {}, outcome_detail: '[secret guard dropped: k0, k1, k2, k3]', dropped: ['k0', 'k1', 'k2', 'k3'],
    });
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
