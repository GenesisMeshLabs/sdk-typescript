import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  BadRequestError, ConflictError, ExecutionRecorder, FileRecordOutbox, GenesisMeshClient, MemoryOutbox, NetworkError,
  ObservationRecorder, OutOfBandRecordError, RateLimitError, RemediationNotRecordedError,
  ServiceUnavailableError, StrictJsonError, ValidationError,
  adminApprovalValid, cancelByRotatingForward, decisionCanonical, parseJson, policyDigest, pythonTimestamp,
  recordOutboxEntry, reviewApprovalProblem, seedSigner, signBreakGlass, signCanonical, signRemediation, urgentAction,
  verifyBoundaryDecision, verifyRemediationRecord,
} from '../src/index.js';
import type {
  AdminApproval, BoundaryDecision, BoundaryEvaluation, BoundaryPolicy, BreakGlassResult, GovernedActionParams,
  RecordOutboxEntry, RecordSubmission, RemediationInput, RemediationStatus, ReviewRecord,
} from '../src/index.js';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { TEST_KEY, mockFetch } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'executor-key');
const directories: string[] = [];
afterEach(async () => {
  jest.restoreAllMocks();
  for (const d of directories.splice(0)) await rm(d, { recursive: true, force: true });
});

const recorded = (extra: Record<string, unknown> = {}) =>
  ({ status: 'recorded', entry: {}, entry_digest: 'd', payload: {}, ...extra }) as unknown as RecordSubmission;

const subject = {
  subject_kind: 'judgement' as const, subject_id: 'judgement-1', change_kind: 'observation' as const,
  change_id: 'observation-1', resource_id: 'kv:v/s',
};

// ── Policies (the coordinator's cross-SDK check) ──────────────────────────────

describe('policy digests with the 1.4.0 sections', () => {
  const interop = parseJson(readFileSync(fileURLToPath(new URL('./fixtures/conformance/interop.json', import.meta.url)), 'utf-8')) as
    { vectors: Array<{ id: string; input: Record<string, unknown> }> };
  const bd = interop.vectors.find(x => x.id === 'bd-001')!.input;
  const policy = (bd['expected_policies'] as BoundaryPolicy[])[0]!;
  const absent = { remediation: null, review_required: null, emergency: null } as unknown as Partial<BoundaryPolicy>;

  it('keeps the 1.3 digest of a policy without them, also when they arrive as null', () => {
    expect(policyDigest(policy)).toMatch(/^7921f8ac/);
    expect(policyDigest({ ...policy, ...absent })).toBe(policyDigest(policy));
  });

  it('verifies a decision against expected policies that carry the sections as null', () => {
    const options = { operatorPublicKeys: bd['operator_public_keys'] as string[], now: new Date(bd['now'] as string) };
    const decision = bd['decision'] as BoundaryDecision;
    expect(verifyBoundaryDecision(decision, { ...options, expectedPolicies: [{ ...policy, ...absent }] }))
      .toMatchObject({ accepted: true });
    // A section present changes the digest: the binding no longer matches.
    expect(verifyBoundaryDecision(decision, {
      ...options, expectedPolicies: [{ ...policy, review_required: true }],
    }).reason).toBe('policy_binding_mismatch');
  });

  it("gives a guided policy the core's digest whether its other sections are absent or null", () => {
    const suite = parseJson(readFileSync(fileURLToPath(new URL('./fixtures/conformance/remediation.json', import.meta.url)), 'utf-8')) as
      { vectors: Array<{ id: string; record?: BoundaryPolicy; expected: { digest?: string } }> };
    const guided = suite.vectors.find(x => x.id === 'policy-with-guidance')!;
    expect(policyDigest(guided.record!)).toBe(guided.expected.digest);
    expect(policyDigest({ ...guided.record!, emergency: null } as unknown as BoundaryPolicy)).toBe(guided.expected.digest);
  });
});

// ── The remediation recorder ──────────────────────────────────────────────────

describe('signRemediation', () => {
  const rotation: RemediationInput = {
    ...subject, steps: 'rotate_forward_then_disable', rotation_evidence_id: 'evidence-2', version_id: 'v3',
    disabled_version_id: 'v2',
  };

  it('signs every field but the signature, absent fields left out, as the executor', async () => {
    const recorder = new ExecutionRecorder({ executorSovereignId: 'controller', signer });
    const record = await recorder.signRemediation({ ...rotation, remediated_at: '2026-01-01T00:05:00.573Z' });
    expect(record).toMatchObject({
      executor_sovereign_id: 'controller', outcome: 'cancelled', remediated_at: '2026-01-01T00:05:00.573000Z',
      signature: { key_id: 'executor-key' },
    });
    expect('detail' in record).toBe(false);
    expect(verifyRemediationRecord(record, [TEST_KEY.pubBase64])).toBe(true);
    expect(verifyRemediationRecord({ ...record, disabled_version_id: 'v1' }, [TEST_KEY.pubBase64])).toBe(false);
    const alerted = await recorder.signRemediation({ ...subject, steps: 'none' });
    expect(alerted.outcome).toBe('alerted');
  });

  it('refuses before signing what the NA would refuse, in its order', async () => {
    const sign = (input: Partial<RemediationInput>) =>
      signRemediation({ ...rotation, ...input, executor_sovereign_id: 'controller' }, signer);
    await expect(sign({ version_id: 'v2' })).rejects.toMatchObject({
      code: 'remediation_malformed', message: 'the forward rotation issues another version than the one disabled',
    });
    await expect(sign({ steps: 'none' })).rejects.toMatchObject({ code: 'remediation_malformed' });
    await expect(sign({ steps: 'disable' })).rejects.toThrow('only a forward rotation names rotation evidence');
    await expect(sign({ outcome: 'alerted' })).rejects.toMatchObject({ code: 'remediation_malformed' });
    await expect(sign({ detail: 'x'.repeat(1025) })).rejects.toMatchObject({ code: 'remediation_malformed' });
    await expect(sign({ remediated_at: '2026-01-01T00:05:00' })).rejects.toMatchObject({ code: 'remediation_malformed' });
    await expect(sign({ version_id: '-----BEGIN PRIVATE KEY-----' })).rejects.toMatchObject({ code: 'remediation_secret_material' });
    await expect(sign({ detail: 'cut \uD83D' })).rejects.toBeInstanceOf(StrictJsonError);
  });
});

// ── The client routes ─────────────────────────────────────────────────────────

function capture(...bodies: unknown[]) {
  const fetch = mockFetch(...bodies.map(body => ({ status: 200, body })));
  const gm = new GenesisMeshClient({
    baseUrl: 'http://na', signingKeyBase64: TEST_KEY.seedBase64, keyId: 'operator-2', audience: 'NA-KEY',
    fetch: fetch as unknown as typeof globalThis.fetch,
  });
  const call = (i: number) => {
    const [url, init] = fetch.mock.calls[i] as [string, RequestInit];
    return { url, method: init.method, body: init.body as string | undefined, headers: init.headers as Record<string, string> };
  };
  return { gm, fetch, call };
}

/** The approval the NA embeds: the request as it received it, with the operator's public key. */
function embedded(request: ReturnType<ReturnType<typeof capture>['call']>, publicKey: string): AdminApproval {
  const url = new URL(request.url);
  return {
    key_id: request.headers['X-Admin-Key-Id']!, public_key: publicKey, method: request.method!, path: url.pathname,
    query: {}, audience: 'NA-KEY', body: parseJson(request.body ?? '{}') as Record<string, unknown>,
    timestamp: request.headers['X-Admin-Timestamp']!, nonce: request.headers['X-Admin-Nonce']!,
    admin_signature: request.headers['X-Admin-Signature']!,
  };
}

describe('the due queue, notices and reviews', () => {
  it('reads the due queue by state and follows its pages', async () => {
    const item = (id: string) => ({ subject_id: id, state: 'remediation_due' }) as RemediationStatus;
    const x = capture(
      { state: 'remediation_due', count: 1, remediations: [item('a')], next_after: '2026-01-01T00:00:00Z|a' },
      { state: 'remediation_due', count: 1, remediations: [item('b')], next_after: null },
    );
    const all: string[] = [];
    for await (const s of x.gm.evidenceStore.allRemediations({ state: 'remediation_due', limit: 1 })) all.push(s.subject_id);
    expect(all).toEqual(['a', 'b']);
    expect(x.call(0).url).toBe('http://na/admin/evidence/remediations?state=remediation_due&limit=1');
    expect(new URL(x.call(1).url).searchParams.get('after')).toBe('2026-01-01T00:00:00Z|a');
    expect(x.call(1).method).toBe('GET');
  });

  it('refuses a cursor that does not advance', async () => {
    const page = { state: null, count: 1, remediations: [{ subject_id: 'a' }], next_after: 'c|a' };
    const x = capture(page, page);
    const read = async () => { for await (const _ of x.gm.evidenceStore.allRemediations()) { /* drain */ } };
    await expect(read()).rejects.toThrow('cursor did not advance');
  });

  it('gets a state and records a notice, with or without a channel', async () => {
    const x = capture({ subject_id: 'j/1', reviews: [], records: [] }, { subject_id: 'j/1' }, { subject_id: 'j/1' });
    await x.gm.evidenceStore.remediation('j/1');
    await x.gm.evidenceStore.markNotified('j/1');
    await x.gm.evidenceStore.markNotified('j/1', 'email');
    expect(x.call(0).url).toBe('http://na/admin/evidence/remediations/j%2F1');
    expect([x.call(1).url, x.call(1).body]).toEqual(['http://na/admin/evidence/remediations/j%2F1/notified', '{}']);
    expect(x.call(2).body).toBe('{"channel":"email"}');
  });

  it('requests a review with exactly the subject and justification, signed as the NA embeds it', async () => {
    const x = capture({ review_id: 'r1', state: 'review_pending' });
    const requested = await x.gm.evidenceStore.requestReview({
      subject_kind: 'judgement', subject_id: 'j1', justification: 'planned with the vendor',
      ...{ extra: 'never sent' },
    } as never);
    expect(requested.review_id).toBe('r1');
    const request = x.call(0);
    expect([request.method, request.url]).toEqual(['POST', 'http://na/admin/evidence/reviews']);
    expect(parseJson(request.body!)).toEqual({ subject_kind: 'judgement', subject_id: 'j1', justification: 'planned with the vendor' });
    expect(adminApprovalValid(embedded(request, TEST_KEY.pubBase64))).toBe(true);
  });

  it('decides a review with a body the embedded approval proves offline', async () => {
    const until = new Date(Date.now() + 86_400_000);
    const x = capture({ review: {}, state: 'waived' }, { review: {}, state: 'review_denied' });
    await x.gm.evidenceStore.decideReview('r1', { verdict: 'waive_until', waive_until: until, note: 'vendor deadline' });
    await x.gm.evidenceStore.decideReview('r2', { verdict: 'deny' });
    const decided = x.call(0);
    expect([decided.method, decided.url]).toEqual(['POST', 'http://na/admin/evidence/reviews/r1/decide']);
    expect(parseJson(decided.body!)).toEqual({ verdict: 'waive_until', waive_until: until.toISOString(), note: 'vendor deadline' });
    expect(x.call(1).body).toBe('{"verdict":"deny"}');

    // The review the NA would sign from it: the approval verifies, and names exactly what was decided.
    const approval = embedded(decided, TEST_KEY.pubBase64);
    const decidedAt = pythonTimestamp(new Date());
    const review: ReviewRecord = {
      review_id: 'r1', subject_kind: 'judgement', subject_id: 'j1', subject_digest: 'a'.repeat(64),
      opened_for: 'flagged_for_review', requested_at: decidedAt, verdict: 'waive_until',
      waive_until: pythonTimestamp(until), note: 'vendor deadline', decided_by: 'operator-2', decider_holder: 'bob',
      approval, decided_at: decidedAt, issuer_sovereign_id: 'na', issued_by: 'na-key',
    };
    expect(reviewApprovalProblem(review, ['NA-KEY'])).toBeNull();
    expect(reviewApprovalProblem({ ...review, note: 'other' }, ['NA-KEY'])).toMatch('another verdict or note');
    expect(reviewApprovalProblem({ ...review, decided_by: 'operator-1' }, ['NA-KEY'])).toMatch('not operator-1');
    expect(reviewApprovalProblem(review, ['OTHER-NA'])).toMatch('another Network Authority');
  });

  it('submits a remediation record on its own route, retried as idempotent', async () => {
    const x = capture({ status: 'recorded', remediation: { state: 'remediated' } });
    const record = await signRemediation({ ...subject, steps: 'none', executor_sovereign_id: 'c' }, signer);
    expect((await x.gm.evidenceStore.submitRemediation(record)).remediation?.state).toBe('remediated');
    expect(x.call(0).url).toBe('http://na/evidence/remediations');
    expect(parseJson(x.call(0).body!)).toEqual({ record });
    expect(x.call(0).headers['X-Admin-Signature']).toBeUndefined();
  });
});

// ── The record outbox ─────────────────────────────────────────────────────────

describe('remediation records in the record outbox', () => {
  function client(recordOutbox = new MemoryOutbox<RecordOutboxEntry>()) {
    const gm = new GenesisMeshClient({
      audience: 'TEST', baseUrl: 'http://unused', fetch: mockFetch({ status: 500, body: {} }) as unknown as typeof fetch,
      recordOutbox,
    });
    return { gm, store: gm.evidenceStore, outbox: recordOutbox };
  }
  const remediation = () => signRemediation({ ...subject, steps: 'none', executor_sovereign_id: 'c' }, signer);

  it('keeps one by its remediation_id and submits it on its route', async () => {
    const { store, outbox } = client();
    const submit = jest.spyOn(store, 'submitRemediation').mockResolvedValue(recorded());
    const record = await remediation();
    expect(recordOutboxEntry(record)).toMatchObject({ id: record.remediation_id, kind: 'remediation' });
    expect(await store.enqueueRecord(record)).toMatchObject({ submission: { status: 'recorded' } });
    expect(submit).toHaveBeenCalledWith(record);
    expect(await outbox.list()).toEqual([]);
  });

  it('retries a subject or rotation not stored yet, and dead-letters a refusal for good', async () => {
    const { store } = client();
    const submit = jest.spyOn(store, 'submitRemediation');
    submit.mockRejectedValueOnce(new ValidationError('submit the rotation first', 'remediation_rotation_missing'));
    expect((await store.enqueueRecord(await remediation())).queued).toMatchObject({ state: 'pending' });
    submit.mockRejectedValueOnce(new ValidationError('no such judgement', 'remediation_subject_not_found'));
    expect((await store.enqueueRecord(await remediation())).queued).toMatchObject({ state: 'pending' });
    submit.mockRejectedValueOnce(new ValidationError('not the plan', 'remediation_steps_mismatch'));
    expect((await store.enqueueRecord(await remediation())).queued).toMatchObject({
      state: 'dead_letter', last_error: { code: 'remediation_steps_mismatch' },
    });
    submit.mockRejectedValueOnce(new ConflictError('nothing due', 'remediation_not_due'));
    expect((await store.enqueueRecord(await remediation())).queued).toMatchObject({ state: 'dead_letter' });
  });

  it('flushes break-glass records, then observations, then remediation records', async () => {
    const { store, outbox } = client();
    const order: string[] = [];
    jest.spyOn(store, 'submitRemediation').mockImplementation(async () => { order.push('remediation'); return recorded(); });
    jest.spyOn(store, 'submitBreakGlass').mockImplementation(async () => { order.push('break_glass'); return recorded(); });
    jest.spyOn(store, 'submitObservations').mockImplementation(async records => {
      order.push('observation');
      return records.map((_, index) => ({ index, ...recorded() }));
    });
    const observation = await new ObservationRecorder({ observerSovereignId: 'o', signer }).record({
      resource_id: 'kv:v/s', action: 'rotate', capability: 'c', changed_at: new Date(Date.now() - 1000), source: 's',
      source_event_id: 'e',
    });
    const breakGlass = await signBreakGlass({
      executor_sovereign_id: 'c', resource_id: 'kv:v/s', resource_action: 'rotate', capability: 'c', justification: 'j',
      evaluation_request: {}, evaluation_failure: 'network_error', outcome: 'success',
    }, signer);
    for (const record of [await remediation(), observation, breakGlass]) await outbox.add(recordOutboxEntry(record));
    const flushed = await store.flushRecords({ ignoreBackoff: true });
    expect(order).toEqual(['break_glass', 'observation', 'remediation']);
    expect(flushed.admitted).toHaveLength(3);
  });

  it('reads remediation entries back from a file outbox', async () => {
    const d = await mkdtemp(join(tmpdir(), 'gm-remediation-'));
    directories.push(d);
    const record = await remediation();
    await new FileRecordOutbox(join(d, 'records')).add(recordOutboxEntry(record));
    expect(await new FileRecordOutbox(join(d, 'records')).list()).toMatchObject([{ kind: 'remediation', record }]);
  });
});

// ── Decisions for the composed flows ──────────────────────────────────────────

const naSigner = seedSigner(TEST_KEY.seedBase64, 'na');
const CONTEXT = 'context-urgent';

async function evaluation(denied: boolean): Promise<BoundaryEvaluation> {
  const e = structuredClone(denied ? v.denied : v.allowed);
  e.decision.context_id = CONTEXT;
  e.decision.decision_made_at = pythonTimestamp(new Date(Date.now() - 1000));
  e.decision.decision_valid_until = pythonTimestamp(new Date(Date.now() + 60_000));
  e.decision.signature = await signCanonical(decisionCanonical(e.decision), naSigner);
  return e;
}

function governed(recordOutbox?: MemoryOutbox<RecordOutboxEntry>) {
  const gm = new GenesisMeshClient({
    audience: 'TEST', baseUrl: 'http://unused', fetch: mockFetch({ status: 500, body: {} }) as unknown as typeof fetch,
    ...(recordOutbox ? { recordOutbox } : {}),
  });
  jest.spyOn(gm.evidenceStore, 'resourceHead').mockResolvedValue(null);
  const submit = jest.spyOn(gm.evidenceStore, 'submit').mockResolvedValue({ status: 'recorded' } as never);
  const recorder = new ExecutionRecorder({ executorSovereignId: 'controller', signer });
  const verify = { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [v.policy], expectedAttestation: v.attestation };
  return { gm, submit, recorder, verify };
}

// ── The cancel pair ───────────────────────────────────────────────────────────

describe('cancelByRotatingForward', () => {
  const due = { ...subject, state: 'remediation_due', mode: 'cancel', steps: 'rotate_forward_then_disable' } as const;

  async function setup(denied = false) {
    const x = governed();
    const steps: string[] = [];
    jest.spyOn(x.gm.boundary, 'evaluate').mockResolvedValue(await evaluation(denied));
    x.submit.mockImplementation(async () => { steps.push('evidence'); return { status: 'recorded' } as never; });
    const submitRemediation = jest.spyOn(x.gm.evidenceStore, 'submitRemediation')
      .mockImplementation(async () => { steps.push('remediation'); return recorded(); });
    const rotate = jest.fn(async (): Promise<{ version_id: string; value?: string }> => {
      steps.push('rotate');
      return { version_id: 'v3', value: 'new secret handle' };
    });
    const disable = jest.fn(async (_version: string) => { steps.push('disable'); });
    const options = {
      remediation: due, deniedVersionId: 'v2', rotate, disable,
      rotation: {
        attestation_id: v.attestation.attestation_id, requested_capability: 'sp-secret.rotate',
        context: { context_id: CONTEXT }, verify: x.verify,
      },
    };
    return { ...x, steps, submitRemediation, rotate, disable, options };
  }

  it('rotates forward under a decision, then disables, then records the linked remediation', async () => {
    const x = await setup();
    const result = await cancelByRotatingForward(x.gm, x.recorder, x.options);
    expect(x.steps).toEqual(['rotate', 'evidence', 'disable', 'remediation']);
    expect(x.disable).toHaveBeenCalledWith('v2');
    const evidence = result.rotation.evidence!;
    expect(evidence).toMatchObject({ resource_id: 'kv:v/s', resource_action: 'rotate', execution_parameters: { version_id: 'v3' } });
    expect(result.remediation).toMatchObject({
      ...subject, executor_sovereign_id: 'controller', outcome: 'cancelled', steps: 'rotate_forward_then_disable',
      rotation_evidence_id: evidence.evidence_id, version_id: 'v3', disabled_version_id: 'v2',
    });
    expect(verifyRemediationRecord(result.remediation!, [TEST_KEY.pubBase64])).toBe(true);
    expect(result).toMatchObject({ rotation: { value: 'new secret handle' }, submission: { status: 'recorded' } });
  });

  it('keeps the record in the record outbox when there is one', async () => {
    const x = await setup();
    const outbox = new MemoryOutbox<RecordOutboxEntry>();
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://unused', recordOutbox: outbox });
    gm.boundary.evaluate = x.gm.boundary.evaluate;
    jest.spyOn(gm.evidenceStore, 'resourceHead').mockResolvedValue(null);
    jest.spyOn(gm.evidenceStore, 'submit').mockResolvedValue({ status: 'recorded' } as never);
    jest.spyOn(gm.evidenceStore, 'submitRemediation').mockRejectedValue(new NetworkError('down'));
    const result = await cancelByRotatingForward(gm, x.recorder, x.options);
    expect(result.queued).toMatchObject({ kind: 'remediation', state: 'pending', id: result.remediation!.remediation_id });
  });

  it('changes nothing when the rotation is denied', async () => {
    const x = await setup(true);
    const result = await cancelByRotatingForward(x.gm, x.recorder, x.options);
    expect(result).toEqual({ rotation: expect.objectContaining({ authorized: false }) });
    expect(x.rotate).not.toHaveBeenCalled();
    expect(x.disable).not.toHaveBeenCalled();
    expect(x.submitRemediation).not.toHaveBeenCalled();
  });

  it('refuses before anything runs when the state or the plan does not call for it', async () => {
    const x = await setup();
    const run = (remediation: object, extra: object = {}) =>
      cancelByRotatingForward(x.gm, x.recorder, { ...x.options, remediation, ...extra } as typeof x.options);
    await expect(run({ ...due, steps: 'disable' })).rejects.toMatchObject({ code: 'remediation_steps_mismatch' });
    await expect(run({ ...due, mode: 'alert_only', steps: 'none' })).rejects.toMatchObject({ code: 'remediation_steps_mismatch' });
    await expect(run({ ...due, state: 'remediated' })).rejects.toMatchObject({ code: 'remediation_already_recorded' });
    await expect(run({ ...due, state: 'upheld' })).rejects.toMatchObject({ code: 'remediation_not_due' });
    await expect(run({ ...due, change_id: null })).rejects.toMatchObject({ code: 'remediation_subject_not_found' });
    await expect(run(due, { deniedVersionId: '-----BEGIN PRIVATE KEY-----' }))
      .rejects.toMatchObject({ code: 'remediation_secret_material' });
    expect(x.steps).toEqual([]);
  });

  it('never disables after a rotation it cannot record', async () => {
    const x = await setup();
    x.rotate.mockImplementation(async () => { x.steps.push('rotate'); return { version_id: 'v2' }; });
    const error = await cancelByRotatingForward(x.gm, x.recorder, x.options).catch(e => e);
    expect(error).toBeInstanceOf(RemediationNotRecordedError);
    expect(error).toMatchObject({ code: 'remediation_not_recorded', cause: { code: 'remediation_malformed' } });
    expect(error.rotation.evidence.execution_parameters).toEqual({ version_id: 'v2' });
    expect(x.disable).not.toHaveBeenCalled();
  });

  it('reports a disable or submission that failed after the rotation, with what is left to do', async () => {
    const x = await setup();
    x.disable.mockRejectedValueOnce(new Error('vault refused'));
    const failed = await cancelByRotatingForward(x.gm, x.recorder, x.options).catch(e => e);
    expect(failed).toMatchObject({ code: 'remediation_not_recorded', cause: { message: 'vault refused' } });
    expect(failed.record).toBeUndefined();
    x.submitRemediation.mockRejectedValueOnce(new ServiceUnavailableError());
    const unsent = await cancelByRotatingForward(x.gm, x.recorder, x.options).catch(e => e);
    expect(unsent).toBeInstanceOf(RemediationNotRecordedError);
    expect(unsent.record).toMatchObject({ version_id: 'v3', disabled_version_id: 'v2' });
  });
});

// ── Urgent changes ────────────────────────────────────────────────────────────

describe('urgentAction', () => {
  const EMERGENCY = 'sp-secret.rotate.emergency';
  const emergencyPolicy = { ...v.policy, policy_id: 'emergency' } as BoundaryPolicy;

  function setup(evaluate: (request: { requested_capability: string }) => Promise<BoundaryEvaluation>) {
    const outbox = new MemoryOutbox<RecordOutboxEntry>();
    const x = governed(outbox);
    const evaluated = jest.spyOn(x.gm.boundary, 'evaluate').mockImplementation(evaluate as never);
    const submitBreakGlass = jest.spyOn(x.gm.evidenceStore, 'submitBreakGlass').mockResolvedValue(recorded());
    const action = jest.fn(async (_decision: BoundaryDecision | null) => ({ value: 'rotated', execution_parameters: { version_id: 'v5' } }));
    const params: GovernedActionParams & { emergency: Parameters<typeof urgentAction>[2]['emergency'] } = {
      attestation_id: v.attestation.attestation_id, requested_capability: 'sp-secret.rotate', resource_id: 'kv:v/s',
      resource_action: 'rotate', context: { context_id: CONTEXT, request_parameters: { lifetime_days: 1 } },
      verify: x.verify,
      emergency: { capability: EMERGENCY, justification: 'key leaked in a public repo', expectedPolicies: [v.policy] },
    };
    return { ...x, outbox, evaluated, submitBreakGlass, action, params };
  }

  it('runs under the ordinary capability when it is allowed', async () => {
    const allowed = await evaluation(false);
    const x = setup(async () => allowed);
    const result = await urgentAction(x.gm, x.recorder, x.params, x.action);
    expect(result).toMatchObject({ path: 'ordinary', result: { authorized: true, value: 'rotated' } });
    expect(x.evaluated).toHaveBeenCalledTimes(1);
    expect(x.evaluated.mock.calls[0]![0]).toMatchObject({ requested_capability: 'sp-secret.rotate' });
  });

  it('NA up with an ordinary DENY: decides under the emergency capability, with its justification', async () => {
    const [denied, allowed] = [await evaluation(true), await evaluation(false)];
    const x = setup(async request => (request.requested_capability === EMERGENCY ? allowed : denied));
    const result = await urgentAction(x.gm, x.recorder, x.params, x.action);
    expect(result).toMatchObject({
      path: 'emergency', ordinaryDenial: { authorized: false }, result: { authorized: true, value: 'rotated' },
    });
    expect(x.evaluated.mock.calls[1]![0]).toMatchObject({
      requested_capability: EMERGENCY,
      context: { request_parameters: { lifetime_days: 1, justification: 'key leaked in a public repo' } },
    });
    expect(x.action).toHaveBeenCalledTimes(1);
    expect(x.action.mock.calls[0]![0]).toBe(allowed.decision);
    expect(x.submit.mock.calls[0]![0]).toMatchObject({ executed_capability: EMERGENCY, execution_parameters: { version_id: 'v5' } });
  });

  it('verifies the emergency decision against the emergency policies', async () => {
    const [denied, allowed] = [await evaluation(true), await evaluation(false)];
    const x = setup(async request => (request.requested_capability === EMERGENCY ? allowed : denied));
    const params = { ...x.params, emergency: { ...x.params.emergency, expectedPolicies: [emergencyPolicy] } };
    await expect(urgentAction(x.gm, x.recorder, params, x.action)).rejects.toMatchObject({ code: 'policy_binding_mismatch' });
    expect(x.action).not.toHaveBeenCalled();
  });

  it.each([
    ['NA down', 'network_error', () => new NetworkError('connection refused')],
    ['NA answering 503', 'server_error', () => new ServiceUnavailableError()],
    ['NA answering 429', 'rate_limited', () => new RateLimitError()],
  ])('%s: breaks the glass naming the emergency capability', async (_case, failure, error) => {
    const x = setup(async () => { throw error(); });
    const outcome = await urgentAction(x.gm, x.recorder, x.params, x.action);
    expect(outcome.path).toBe('break_glass');
    const result = outcome.result as BreakGlassResult<string>;
    expect(x.action).toHaveBeenCalledWith(null);
    expect(result).toMatchObject({ brokeGlass: true, failure, value: 'rotated', submission: { status: 'recorded' } });
    expect(result.record).toMatchObject({
      capability: EMERGENCY, evaluation_failure: failure, justification: 'key leaked in a public repo',
      request_parameters: { lifetime_days: 1, justification: 'key leaked in a public repo' },
      execution_parameters: { version_id: 'v5' },
    });
  });

  it('never breaks the glass on a refusal, and checks break-glass before evaluating', async () => {
    const x = setup(async () => { throw new BadRequestError('bad request'); });
    await expect(urgentAction(x.gm, x.recorder, x.params, x.action)).rejects.toBeInstanceOf(BadRequestError);
    expect(x.action).not.toHaveBeenCalled();
    const noOutbox = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://unused' });
    const evaluate = jest.spyOn(noOutbox.boundary, 'evaluate');
    await expect(urgentAction(noOutbox, x.recorder, x.params, x.action)).rejects.toMatchObject({ code: 'record_outbox_required' });
    await expect(urgentAction(x.gm, x.recorder, { ...x.params, emergency: { ...x.params.emergency, justification: '' } }, x.action))
      .rejects.toBeInstanceOf(OutOfBandRecordError);
    expect(evaluate).not.toHaveBeenCalled();
  });
});
