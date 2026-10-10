import { mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  ExecutionRecorder, FileOutbox, FileRecordOutbox, GenesisMeshClient, MemoryOutbox, NetworkError, ObservationRecorder,
  RateLimitError, ServiceUnavailableError, ValidationError, BadRequestError, GovernedActionError, OutOfBandRecordError,
  GenesisMeshError,
  decisionCanonical, governedAction, pythonTimestamp, recordOutboxEntry, seedSigner, signCanonical,
  verifyOutOfBandRecord,
} from '../src/index.js';
import type {
  BreakGlassResult, GovernedActionParams, ObservationBatchResult, ObservationRecord, RecordOutboxEntry, RecordSubmission,
} from '../src/index.js';
import { TEST_KEY, mockFetch } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'test');
const directories: string[] = [];
afterEach(async () => {
  jest.restoreAllMocks();
  for (const d of directories.splice(0)) await rm(d, { recursive: true, force: true });
});
async function directory(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'gm-records-'));
  directories.push(d);
  return join(d, 'records');
}

const observer = new ObservationRecorder({ observerSovereignId: 'cloud-observer', signer });
function observe(n: number): Promise<ObservationRecord> {
  return observer.record({
    resource_id: `kv:prod/s${n}`, action: 'rotate', capability: 'secret.rotate', changed_at: new Date(Date.now() - 60_000),
    source: 'cloud-activity-log', source_event_id: `event-${n}`,
  });
}
const recorded = (status: RecordSubmission['status'] = 'recorded') =>
  ({ status, entry: {}, entry_digest: 'd', payload: {} }) as unknown as RecordSubmission;

function client(recordOutbox = new MemoryOutbox<RecordOutboxEntry>()) {
  const gm = new GenesisMeshClient({
    audience: 'TEST', baseUrl: 'http://unused', fetch: mockFetch({ status: 500, body: {} }) as unknown as typeof fetch,
    recordOutbox,
  });
  return { gm, store: gm.evidenceStore, outbox: recordOutbox };
}

describe('FileRecordOutbox', () => {
  it('keeps records in their own versioned format, in order', async () => {
    const dir = await directory();
    const first = recordOutboxEntry(await observe(1));
    await new FileRecordOutbox(dir).add(first);
    await new FileRecordOutbox(dir).add(recordOutboxEntry(await observe(2)));
    const listed = await new FileRecordOutbox(dir).list();
    expect(listed.map(e => [e.kind, e.id])).toEqual([['observation', first.id], ['observation', listed[1]!.id]]);
    const [file] = (await readdir(dir)).sort();
    expect(JSON.parse(await readFile(join(dir, file!), 'utf-8')).format).toBe('gm.evidence.record-outbox.v1');
  });
  it('refuses a directory that holds execution records', async () => {
    const dir = await directory();
    await new FileOutbox(dir).add({
      id: 'e', evidence: { evidence_id: 'e' } as never, state: 'pending', attempts: 0,
      queued_at: '2026-10-09T00:00:00.000Z', next_attempt_at: null, last_error: null,
    });
    await expect(new FileRecordOutbox(dir).list()).rejects.toThrow('gm.evidence.record-outbox.v1');
  });
});

describe('enqueueRecord and flushRecords', () => {
  it('needs a record outbox', async () => {
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://unused' });
    await expect(gm.evidenceStore.enqueueRecord(await observe(1))).rejects.toMatchObject({ code: 'record_outbox_required' });
  });
  it('removes an admitted record and keeps a transient failure pending', async () => {
    const { store, outbox } = client();
    const submit = jest.spyOn(store, 'submitObservation')
      .mockResolvedValueOnce(recorded())
      .mockRejectedValueOnce(new NetworkError('down'));
    expect((await store.enqueueRecord(await observe(1))).submission?.status).toBe('recorded');
    const delivery = await store.enqueueRecord(await observe(2));
    expect(delivery.queued).toMatchObject({ state: 'pending', attempts: 1, last_error: { code: 'network_error' } });
    expect(submit).toHaveBeenCalledTimes(2);
    expect((await outbox.list()).length).toBe(1);
  });
  it('dead-letters a refusal no retry can overcome, and retries an unknown key', async () => {
    const { store } = client();
    jest.spyOn(store, 'submitObservation')
      .mockRejectedValueOnce(new ValidationError('bad signature', 'observation_invalid_signature'))
      .mockRejectedValueOnce(new ValidationError('unknown key', 'observation_unknown_key'));
    expect((await store.enqueueRecord(await observe(1))).queued?.state).toBe('dead_letter');
    expect((await store.enqueueRecord(await observe(2))).queued?.state).toBe('pending');
  });
  it('refuses a different record under an id already queued', async () => {
    const { store } = client();
    jest.spyOn(store, 'submitObservation').mockRejectedValue(new NetworkError('down'));
    const record = await observe(1);
    await store.enqueueRecord(record);
    await expect(store.enqueueRecord({ ...record, action: 'delete' })).rejects.toThrow('a different record');
  });
  it('flushes observations in batches and settles each result', async () => {
    const { store, outbox } = client();
    jest.spyOn(store, 'submitObservation').mockRejectedValue(new NetworkError('down'));
    for (let n = 0; n < 4; n++) await store.enqueueRecord(await observe(n));
    const batch = jest.spyOn(store, 'submitObservations').mockImplementation(async records => records.map((_, index) => (
      index === 1 ? { index, status: 'refused', error: { code: 'observation_out_of_scope', message: 'out of scope' } }
        : index === 2 ? { index, status: 'quarantined' }
          : { index, status: 'recorded' }
    ) as ObservationBatchResult));
    const result = await store.flushRecords({ ignoreBackoff: true });
    expect(batch).toHaveBeenCalledTimes(1);
    expect(result.admitted.length).toBe(3);
    expect(result.quarantined.length).toBe(1);
    expect(result.dead_lettered.map(e => e.last_error?.code)).toEqual(['observation_out_of_scope']);
    expect((await outbox.list()).map(e => e.state)).toEqual(['dead_letter']);
  });
  it('stops a run at a transient failure and skips records in backoff', async () => {
    const { store } = client();
    jest.spyOn(store, 'submitObservation').mockRejectedValue(new NetworkError('down'));
    await store.enqueueRecord(await observe(1));
    expect((await store.flushRecords()).pending.length).toBe(1);
    const batch = jest.spyOn(store, 'submitObservations').mockRejectedValue(new ServiceUnavailableError());
    expect((await store.flushRecords({ ignoreBackoff: true })).pending.length).toBe(1);
    expect(batch).toHaveBeenCalledTimes(1);
  });
  it('tries each observation alone when the batch itself is refused', async () => {
    const { store } = client();
    const single = jest.spyOn(store, 'submitObservation').mockRejectedValueOnce(new NetworkError('down'));
    await store.enqueueRecord(await observe(1));
    jest.spyOn(store, 'submitObservations').mockRejectedValue(new BadRequestError('no batch', 'invalid_observation'));
    single.mockResolvedValue(recorded());
    expect((await store.flushRecords({ ignoreBackoff: true })).admitted.length).toBe(1);
  });
});

describe('governedAction with breakGlass', () => {
  async function setup(evaluate: () => Promise<unknown>) {
    const { gm, outbox } = client();
    jest.spyOn(gm.boundary, 'evaluate').mockImplementation(evaluate as never);
    const submit = jest.spyOn(gm.evidenceStore, 'submitBreakGlass').mockResolvedValue(recorded());
    jest.spyOn(gm.evidenceStore, 'resourceHead').mockResolvedValue(null);
    jest.spyOn(gm.evidenceStore, 'submit').mockResolvedValue({ status: 'recorded' } as never);
    const recorder = new ExecutionRecorder({ executorSovereignId: 'executor', signer });
    const params: GovernedActionParams & { breakGlass: { justification: string } } = {
      attestation_id: v.attestation.attestation_id, requested_capability: 'sp-secret.rotate',
      resource_id: 'kv:v/s', resource_action: 'rotate', context: { attributes: { owner: 'team-a' } },
      verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [v.policy], expectedAttestation: v.attestation },
      breakGlass: { justification: 'incident 42: rotate the leaked key now' },
    };
    const action = jest.fn(async (_decision: unknown) => ({ value: 'done', execution_parameters: { version_id: 'v9' } }));
    return { gm, outbox, submit, recorder, params, action };
  }

  it.each([
    ['network_error', () => new NetworkError('connection refused')],
    ['timeout', () => Object.assign(new NetworkError('timed out'), { cause: Object.assign(new Error('t'), { name: 'TimeoutError' }) })],
    ['server_error', () => new ServiceUnavailableError()],
    ['rate_limited', () => new RateLimitError()],
  ])('runs the action and records %s', async (failure, error) => {
    const x = await setup(async () => { throw error(); });
    const result = await governedAction(x.gm, x.recorder, x.params, x.action) as BreakGlassResult<string>;
    expect(x.action).toHaveBeenCalledWith(null);
    expect(result).toMatchObject({ brokeGlass: true, failure, value: 'done', submission: { status: 'recorded' } });
    expect(result.record).toMatchObject({
      executor_sovereign_id: 'executor', resource_id: 'kv:v/s', resource_action: 'rotate', capability: 'sp-secret.rotate',
      attestation_id: v.attestation.attestation_id, attributes: { owner: 'team-a' }, evaluation_failure: failure,
      execution_parameters: { version_id: 'v9' }, outcome: 'success',
    });
    expect(verifyOutOfBandRecord(result.record, [TEST_KEY.pubBase64])).toBe(true);
  });
  it('never breaks the glass on a DENY or a refused request', async () => {
    const denied = structuredClone(v.denied);
    denied.decision.decision_made_at = pythonTimestamp(new Date(Date.now() - 1000));
    denied.decision.decision_valid_until = pythonTimestamp(new Date(Date.now() + 60_000));
    denied.decision.signature = await signCanonical(decisionCanonical(denied.decision), signer);
    const deny = await setup(async () => denied);
    deny.params.context = { ...deny.params.context, context_id: denied.decision.context_id };
    expect(await governedAction(deny.gm, deny.recorder, deny.params, deny.action)).toMatchObject({ authorized: false });
    const refused = await setup(async () => { throw new BadRequestError('bad request'); });
    await expect(governedAction(refused.gm, refused.recorder, refused.params, refused.action)).rejects.toBeInstanceOf(BadRequestError);
    for (const x of [deny, refused]) {
      expect(x.action).not.toHaveBeenCalled();
      expect(await x.outbox.list()).toEqual([]);
    }
  });
  it('checks what it needs before anything runs', async () => {
    const x = await setup(async () => { throw new NetworkError('down'); });
    const noOutbox = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://unused' });
    await expect(governedAction(noOutbox, x.recorder, x.params, x.action)).rejects.toMatchObject({ code: 'record_outbox_required' });
    await expect(governedAction(x.gm, x.recorder, { ...x.params, breakGlass: { justification: '' } }, x.action))
      .rejects.toBeInstanceOf(OutOfBandRecordError);
    await expect(governedAction(x.gm, x.recorder, { ...x.params, resource_id: undefined, resource_action: undefined }, x.action))
      .rejects.toThrow('breakGlass needs resource_id');
    expect(x.action).not.toHaveBeenCalled();
  });
  it('records a failed action and rethrows its error', async () => {
    const x = await setup(async () => { throw new NetworkError('down'); });
    x.action.mockRejectedValue(new Error('cloud refused'));
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toThrow('cloud refused');
    expect(x.submit.mock.calls[0]![0]).toMatchObject({ outcome: 'failure', outcome_detail: 'action failed' });
  });
  it('wraps the error when a failed action cannot be recorded', async () => {
    const x = await setup(async () => { throw new NetworkError('down'); });
    x.action.mockRejectedValue(new Error('cloud refused'));
    jest.spyOn(x.outbox, 'add').mockRejectedValue(new Error('disk full'));
    await expect(governedAction(x.gm, x.recorder, x.params, x.action)).rejects.toBeInstanceOf(GovernedActionError);
  });
  it('keeps the record pending when the NA is still down, and leaves refused metadata out', async () => {
    const x = await setup(async () => { throw new NetworkError('down'); });
    x.submit.mockRejectedValue(new NetworkError('down'));
    x.action.mockResolvedValue({ value: 'done', execution_parameters: { version_id: 'v9', client_secret: 'x' } } as never);
    const result = await governedAction(x.gm, x.recorder, x.params, x.action) as BreakGlassResult<string>;
    expect(result.queued?.state).toBe('pending');
    expect(result.dropped).toEqual(['client_secret']);
    expect(result.record.execution_parameters).toEqual({ version_id: 'v9' });
  });
});

describe('review fixes (1.3.0)', () => {
  it('breakGlass needs an attestation-based evaluation', async () => {
    const { gm } = client();
    const recorder = new ExecutionRecorder({ executorSovereignId: 'executor', signer });
    const params = {
      agreement: { agreement_id: 'a' } as never, requested_capability: 'sp-secret.rotate', resource_id: 'kv:v/s',
      resource_action: 'rotate' as const,
      verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [] },
      breakGlass: { justification: 'outage' },
    };
    await expect(governedAction(gm, recorder, params, async () => ({}))).rejects.toMatchObject({ code: 'break_glass_malformed' });
  });
  it.each(['admin_auth_throttled', 'evidence_store_unavailable'])('%s never breaks the glass', async code => {
    const { gm, outbox } = client();
    const status = code === 'admin_auth_throttled' ? 429 : 503;
    jest.spyOn(gm.boundary, 'evaluate').mockRejectedValue(new GenesisMeshError('refused', code, status));
    const recorder = new ExecutionRecorder({ executorSovereignId: 'executor', signer });
    const action = jest.fn(async () => ({}));
    await expect(governedAction(gm, recorder, {
      attestation_id: 'att', requested_capability: 'c', resource_id: 'kv:v/s', resource_action: 'rotate',
      verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [] }, breakGlass: { justification: 'x' },
    }, action)).rejects.toMatchObject({ code });
    expect(action).not.toHaveBeenCalled();
    expect(await outbox.list()).toEqual([]);
  });
  it('a removal is never undone by an update in flight', async () => {
    const dir = await directory();
    const outbox = new FileRecordOutbox(dir);
    const entry = recordOutboxEntry(await observe(1));
    await outbox.add(entry);
    await Promise.all([outbox.update({ ...entry, attempts: 1 }), outbox.remove(entry.id)]);
    expect(await new FileRecordOutbox(dir).list()).toEqual([]);
  });
});
