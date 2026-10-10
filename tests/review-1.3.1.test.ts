/**
 * Regression tests for the fixes in 1.3.1, one block per review finding.
 * Sizes and messages expected from the metadata guard were taken from the
 * Python reference's `metadata_problem`, run over the same values.
 */
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  BadRequestError, EvidenceStoreClient, ExecutionRecorder, FileOutbox, GenesisMeshClient, MemoryOutbox,
  MetadataRefusedError, NetworkError, ObservationRecorder, OutOfBandRecordError, RateLimitError, StrictJsonError,
  checkMetadataOnly, classifySubmissionError, decisionCanonical, entryDigest, executionDigest, governedAction,
  metadataProblem, nextAttemptAt, observationFromFinding, observationId, parseExportLines, payloadDigest,
  pythonTimestamp, reconcileResources, recordOutboxEntry, seedSigner, signBreakGlass, signCanonical,
  verifyEvidenceEvents, verifyOutOfBandRecord, LOCAL_ERROR, PERMANENT_REFUSALS, RECORD_PERMANENT_REFUSALS,
} from '../src/index.js';
import { HttpTransport } from '../src/client.js';
import { evaluationFailure } from '../src/governance.js';
import type {
  BreakGlassResult, EvidenceEvent, ExecutionEvidence, ExecutorKeyInfo, GovernedActionParams, ObservationBatchResult,
  ObservationRecord, RecordOutboxEntry, RecordSubmission, ReconciliationFinding,
} from '../src/index.js';
import { TEST_KEY, mockFetch } from './helpers.js';
import { vectors } from './vectors.js';

const v = vectors();
const signer = seedSigner(TEST_KEY.seedBase64, 'test');
const observer = new ObservationRecorder({ observerSovereignId: 'cloud-observer', signer });
const recorder = new ExecutionRecorder({ executorSovereignId: 'executor', signer });
const DECISION = { decision_id: 'd1', context_id: 'c1', agreement_id: 'a1' };
const observation = { resource_id: 'kv:prod/a', action: 'rotate' as const, capability: 'secret.rotate', source: 'log' };
const breakGlass = {
  executor_sovereign_id: 'executor', resource_id: 'kv:prod/a', resource_action: 'rotate' as const,
  capability: 'secret.rotate', justification: 'incident 42', evaluation_request: { a: 1 },
  evaluation_failure: 'timeout' as const, outcome: 'success',
};
const recorded = () => ({ status: 'recorded', entry: {}, entry_digest: 'd', payload: {} }) as unknown as RecordSubmission;

const directories: string[] = [];
afterEach(async () => {
  jest.restoreAllMocks();
  for (const d of directories.splice(0)) await rm(d, { recursive: true, force: true });
});
async function directory(): Promise<string> {
  const d = await mkdtemp(join(tmpdir(), 'gm-131-'));
  directories.push(d);
  return join(d, 'outbox');
}
function client(options: { recordOutbox?: MemoryOutbox<RecordOutboxEntry>; outbox?: MemoryOutbox | FileOutbox } = {}) {
  const gm = new GenesisMeshClient({
    audience: 'TEST', baseUrl: 'http://unused', fetch: mockFetch({ status: 500, body: {} }) as unknown as typeof fetch,
    recordOutbox: options.recordOutbox ?? new MemoryOutbox<RecordOutboxEntry>(), outbox: options.outbox,
  });
  return { gm, store: gm.evidenceStore };
}
const observe = (n: number) => observer.record({
  ...observation, resource_id: `kv:prod/s${n}`, changed_at: new Date(Date.now() - 60_000), source_event_id: `event-${n}`,
});

describe('finding 1: the metadata guard is the reference\'s metadata_problem', () => {
  it('sizes values as escaped canonical JSON, as the reference counts them', () => {
    // Python: metadata_problem({'metadata': {'note': 'é' * 3000}}); 6027 bytes as UTF-8.
    expect(metadataProblem({ metadata: { note: 'é'.repeat(3000) } })).toBe('metadata is 18024 bytes, over the 16384-byte limit');
    // An emoji is a surrogate pair: 12 bytes escaped.
    expect(metadataProblem({ metadata: { note: '😀 '.repeat(1260) } })).toBe('metadata is 16404 bytes, over the 16384-byte limit');
    expect(metadataProblem({ metadata: { note: '😀 '.repeat(1250) } })).toBeNull();
  });
  it('refuses an observation whose non-ASCII metadata the NA would refuse', async () => {
    await expect(observer.record({
      ...observation, changed_at: new Date(), source_event_id: 'e', metadata: { note: 'é'.repeat(3000) },
    })).rejects.toMatchObject({ code: 'observation_secret_material', message: expect.stringContaining('over the 16384-byte limit') });
  });
  it('checks the actor, source event and version, as the reference does', async () => {
    for (const [field, value, message] of [
      ['actor', 'A'.repeat(130), "field 'actor' looks like key or token material"],
      // The reference's `$` matches before a final newline.
      ['actor', `${'A'.repeat(130)}\n`, "field 'actor' looks like key or token material"],
      ['source_event_id', 'eyJhbGciOi.eyJzdWIiOi.abc', "field 'source_event_id' looks like key or token material"],
      ['version_id', '-----BEGIN X', "field 'version_id' contains a PEM block"],
    ] as const) {
      await expect(observer.record({ ...observation, changed_at: new Date(), source_event_id: 'e', [field]: value }))
        .rejects.toMatchObject({ code: 'observation_secret_material', message });
    }
  });
  it('counts the justification in the size and in characters, and names it when it refuses it', async () => {
    const attributes = { note: 'x '.repeat(15 * 512) };
    await expect(signBreakGlass({ ...breakGlass, attributes, justification: 'j '.repeat(512) }, signer))
      .rejects.toMatchObject({ code: 'break_glass_secret_material', message: 'metadata is 16499 bytes, over the 16384-byte limit' });
    // 1020 characters, 1040 UTF-16 units.
    const emoji = 'Rotate the leaked key now. '.repeat(37).slice(0, 1000) + '🚨'.repeat(20);
    const record = await signBreakGlass({ ...breakGlass, justification: emoji }, signer);
    expect(verifyOutOfBandRecord(record, [TEST_KEY.pubBase64])).toBe(true);
    await expect(signBreakGlass({ ...breakGlass, justification: 'x'.repeat(1005) + '🚨'.repeat(20) }, signer))
      .rejects.toMatchObject({ code: 'break_glass_malformed' });
    // Finding 10: a refused justification is reported as the justification.
    await expect(signBreakGlass({ ...breakGlass, justification: 'see -----BEGIN' }, signer))
      .rejects.toMatchObject({ code: 'break_glass_secret_material', message: "field 'justification' contains a PEM block" });
    await expect(signBreakGlass({ ...breakGlass, outcome_detail: 'é'.repeat(1025) }, signer))
      .rejects.toMatchObject({ code: 'break_glass_malformed' });
  });

  describe('governedAction with breakGlass', () => {
    function setup() {
      const { gm, store } = client();
      jest.spyOn(gm.boundary, 'evaluate').mockRejectedValue(new NetworkError('down'));
      jest.spyOn(store, 'submitBreakGlass').mockRejectedValue(new NetworkError('down'));
      const params: GovernedActionParams & { breakGlass: { justification: string } } = {
        attestation_id: 'att-1', requested_capability: 'secret.rotate', resource_id: 'kv:prod/a', resource_action: 'rotate',
        verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [] }, breakGlass: { justification: 'x' },
      };
      const action = jest.fn(async () => ({ value: 'rotated' }));
      return { gm, store, params, action };
    }
    it('keeps the record of a justification ending in emoji', async () => {
      const x = setup();
      x.params.breakGlass.justification = 'Rotate the leaked key now. '.repeat(37).slice(0, 1000) + '🚨'.repeat(20);
      const result = await governedAction(x.gm, recorder, x.params, x.action) as BreakGlassResult<string>;
      expect(result).toMatchObject({ brokeGlass: true, value: 'rotated', queued: { state: 'pending' } });
    });
    it('refuses, before the action runs, a context the record could not hold as the reference sizes it', async () => {
      const x = setup();
      // 7200 bytes as UTF-8, 16800 escaped.
      const params = { ...x.params, context: { attributes: { note: 'é '.repeat(2400) } } };
      await expect(governedAction(x.gm, recorder, params, x.action)).rejects.toBeInstanceOf(OutOfBandRecordError);
      expect(x.action).not.toHaveBeenCalled();
    });
  });
});

describe('finding 2: string timestamps are signed in the reference\'s form', () => {
  it.each([
    ['toISOString() output', '2026-10-10T08:00:00.573Z', '2026-10-10T08:00:00.573000Z'],
    ['+00:00', '2026-10-10T08:00:00+00:00', '2026-10-10T08:00:00Z'],
    ['a seven-digit fraction (cut, as the reference reads it)', '2026-10-10T08:00:00.1234567Z', '2026-10-10T08:00:00.123456Z'],
    ['another offset', '2026-10-10T10:00:00.5+02:00', '2026-10-10T08:00:00.500000Z'],
    ['a zero fraction', '2026-10-10T08:00:00.000Z', '2026-10-10T08:00:00Z'],
  ])('converts %s', async (_, given, signed) => {
    const record = await observer.record({ ...observation, changed_at: given, observed_at: '2026-10-10T09:00:00Z', source_event_id: given });
    expect(record.changed_at).toBe(signed);
    expect(verifyOutOfBandRecord(record, [TEST_KEY.pubBase64])).toBe(true);
  });
  it.each(['2026-10-10T08:00:00', 'yesterday', '2026-02-30T08:00:00Z', '2026-10-10T24:00:00Z'])('refuses %s before signing', async given => {
    await expect(observer.record({ ...observation, changed_at: given, source_event_id: 'e' }))
      .rejects.toMatchObject({ code: 'observation_malformed' });
  });
  it('converts a break-glass record\'s time', async () => {
    const record = await signBreakGlass({ ...breakGlass, executed_at: '2026-10-10T08:00:00.573Z' }, signer);
    expect(record.executed_at).toBe('2026-10-10T08:00:00.573000Z');
    expect(verifyOutOfBandRecord(record, [TEST_KEY.pubBase64])).toBe(true);
  });
  it('orders a window to the microsecond (finding 10)', async () => {
    await expect(observer.record({
      ...observation, source_event_id: 'w',
      changed_not_before: '2026-10-10T08:00:00.000500Z', changed_not_after: '2026-10-10T08:00:00.000100Z',
    })).rejects.toMatchObject({ code: 'observation_malformed', message: 'changed_not_before is after changed_not_after' });
  });
});

describe('finding 3: break-glass only on an outage', () => {
  function routed(sovereign: () => Response) {
    const calls: string[] = [];
    const fetch = jest.fn(async (url: string | URL | Request) => {
      const u = String(url);
      calls.push(u);
      if (u.endsWith('/sovereign.json')) return sovereign();
      return new Response(JSON.stringify({ error: { code: 'down', message: 'down' } }), { status: 503 });
    });
    const gm = new GenesisMeshClient({
      baseUrl: 'http://na.test', signingKeyBase64: TEST_KEY.seedBase64, keyId: 'op',
      fetch: fetch as unknown as typeof globalThis.fetch, recordOutbox: new MemoryOutbox<RecordOutboxEntry>(),
    });
    return { gm, calls };
  }
  const params: GovernedActionParams & { breakGlass: { justification: string } } = {
    attestation_id: 'att-1', requested_capability: 'secret.rotate', resource_id: 'kv:prod/a', resource_action: 'rotate',
    verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [] }, breakGlass: { justification: 'incident 42' },
  };
  it.each([
    ['a firewall\'s 403 page', () => new Response('<html>blocked</html>', { status: 403 }), 403],
    ['a 404', () => new Response(JSON.stringify({ error: 'not found' }), { status: 404 }), 404],
    ['a 200 without the key', () => new Response(JSON.stringify({ hello: 1 }), { status: 200 }), 200],
  ])('keeps the status of %s and never breaks the glass', async (_, sovereign, status) => {
    const { gm, calls } = routed(sovereign);
    const action = jest.fn(async () => ({}));
    const error = await governedAction(gm, recorder, params, action).catch(e => e);
    expect(error).toMatchObject({ code: 'na_public_key_unavailable', status });
    expect(evaluationFailure(error)).toBeNull();
    expect(action).not.toHaveBeenCalled();
    expect(calls).toEqual(['http://na.test/sovereign.json']);
  });
  it('breaks the glass when the lookup gets no answer, or the NA is down', async () => {
    const unreachable = routed(() => { throw Object.assign(new TypeError('fetch failed'), { cause: { code: 'ECONNREFUSED' } }); });
    const down = routed(() => new Response('{}', { status: 503 }));
    for (const [{ gm }, failure] of [[unreachable, 'network_error'], [down, 'server_error']] as const) {
      const result = await governedAction(gm, recorder, params, async () => ({})) as BreakGlassResult<unknown>;
      expect(result).toMatchObject({ brokeGlass: true, failure });
    }
  });
  it('names a lookup that timed out a timeout', async () => {
    const t = new HttpTransport({
      baseUrl: 'http://na.test', signingKeyBase64: TEST_KEY.seedBase64,
      fetch: (async () => { throw Object.assign(new Error('timed out'), { name: 'TimeoutError' }); }) as unknown as typeof fetch,
    });
    const error = await t.adminPost('/admin/boundary/evaluate', {}).catch(e => e);
    expect(error).toBeInstanceOf(NetworkError);
    expect(evaluationFailure(error)).toBe('timeout');
  });
});

describe('finding 4: a record the NA cannot read never poisons the outbox', () => {
  const nested = (depth: number): Record<string, unknown> => (depth === 1 ? { a: 1 } : { a: nested(depth - 1) });
  it('refuses, before signing, values the NA\'s strict reader refuses', async () => {
    const record = (extra: object) => recorder.record({ decision: DECISION, executed_capability: 'c', outcome: 'success', ...extra });
    await expect(record({ outcome_detail: 'deploy ok \u{1F680}'.slice(0, 11) })).rejects.toMatchObject({ code: 'lone_surrogate' });
    await expect(record({ execution_parameters: { n: 2n ** 64n } })).rejects.toMatchObject({ code: 'integer_out_of_range' });
    await expect(record({ execution_parameters: { n: 1e20 } })).rejects.toMatchObject({ code: 'integer_out_of_range' });
    // Room is left for the request and the export that carry the record.
    await expect(record({ execution_parameters: nested(62) })).rejects.toMatchObject({ code: 'invalid_json' });
    await expect(record({ execution_parameters: nested(61) })).resolves.toMatchObject({ outcome: 'success' });
    await expect(observer.record({ ...observation, changed_at: new Date(), source_event_id: 'e', metadata: { s: '\ud83d' } }))
      .rejects.toBeInstanceOf(StrictJsonError);
  });
  it('records the outcome without a value the NA could not read, after the action ran', async () => {
    const { gm, store } = client({ outbox: new MemoryOutbox() });
    const evaluation = structuredClone(v.allowed);
    evaluation.decision.decision_made_at = pythonTimestamp(new Date(Date.now() - 1000));
    evaluation.decision.decision_valid_until = pythonTimestamp(new Date(Date.now() + 60_000));
    evaluation.decision.signature = await signCanonical(decisionCanonical(evaluation.decision), signer);
    jest.spyOn(gm.boundary, 'evaluate').mockResolvedValue(evaluation);
    jest.spyOn(store, 'resourceHead').mockResolvedValue(null);
    const submit = jest.spyOn(store, 'submit').mockResolvedValue({ status: 'recorded' } as never);
    const error = await governedAction(gm, recorder, {
      attestation_id: v.attestation.attestation_id, requested_capability: 'sp-secret.rotate', resource_id: 'kv:v/s',
      resource_action: 'rotate', context: { context_id: evaluation.decision.context_id },
      verify: { operatorPublicKeys: [TEST_KEY.pubBase64], expectedPolicies: [v.policy], expectedAttestation: v.attestation },
    }, async () => ({ value: 'v', outcome_detail: 'cut \u{1F680}'.slice(0, 5), execution_parameters: { version: 'v2' } }))
      .catch(e => e);
    expect(error).toBeInstanceOf(MetadataRefusedError);
    expect(error.cause).toBeInstanceOf(StrictJsonError);
    expect(error).toMatchObject({
      dropped: ['outcome_detail'], evidence: { execution_parameters: { version: 'v2' }, outcome_detail: '[secret guard dropped: outcome_detail]' },
    });
    expect(submit).toHaveBeenCalledWith(error.evidence);
  });
  it('treats invalid_json from the NA as final', () => {
    const refused = new BadRequestError('request body is not accepted JSON (lone_surrogate)', 'invalid_json');
    expect(PERMANENT_REFUSALS.has('invalid_json') && RECORD_PERMANENT_REFUSALS.has('invalid_json')).toBe(true);
    expect(classifySubmissionError(refused).transient).toBe(false);
    expect(classifySubmissionError(refused, RECORD_PERMANENT_REFUSALS).transient).toBe(false);
  });
  it('splits a batch the NA refuses until it finds the record', async () => {
    const { store } = client();
    jest.spyOn(store, 'submitObservation').mockRejectedValue(new NetworkError('down'));
    for (let n = 0; n < 5; n++) await store.enqueueRecord(await observe(n));
    const unreadable = () => new BadRequestError('request body is not accepted JSON (lone_surrogate)', 'invalid_json');
    const batch = jest.spyOn(store, 'submitObservations').mockImplementation(async records => {
      if (records.some(r => r.source_event_id === 'event-3')) throw unreadable();
      return records.map((_, index) => ({ index, status: 'recorded' }) as ObservationBatchResult);
    });
    const single = jest.spyOn(store, 'submitObservation').mockImplementation(async record => {
      if (record.source_event_id === 'event-3') throw unreadable();
      return recorded();
    });
    const result = await store.flushRecords({ ignoreBackoff: true });
    expect(result.admitted).toHaveLength(4);
    expect(result.dead_lettered.map(e => [(e.record as ObservationRecord).source_event_id, e.last_error?.code]))
      .toEqual([['event-3', 'invalid_json']]);
    // 5, then 3 and 2; the 2 alone, each.
    expect(batch.mock.calls.map(c => c[0].length)).toEqual([5, 3, 2]);
    expect(single).toHaveBeenCalledTimes(2 + 5);
  });
  it('moves an unreadable outbox file aside once, naming it, and goes on', async () => {
    const dir = await directory();
    const good = await recorder.record({ decision: DECISION, executed_capability: 'c', outcome: 'success' });
    await new FileOutbox(dir).add({
      id: good.evidence_id, evidence: good, state: 'pending', attempts: 0, queued_at: '2026-10-10T00:00:00.000Z',
      next_attempt_at: null, last_error: null,
    });
    // A record 1.3.0 signed with a lone surrogate: its file can no longer be read.
    await writeFile(join(dir, '000000000002-bad.json'),
      '{"entry":{"id":"bad","evidence":{"outcome_detail":"\\ud83d"}},"format":"gm.evidence.outbox.v1"}\n', 'utf-8');
    const outbox = new FileOutbox(dir);
    await expect(outbox.list()).rejects.toMatchObject({
      code: 'outbox_file_unreadable', message: expect.stringContaining('000000000002-bad.json'),
    });
    expect((await outbox.list()).map(e => e.id)).toEqual([good.evidence_id]);
    expect(await readdir(dir)).toContain('000000000002-bad.json.unreadable');
    expect((await new FileOutbox(dir).list()).map(e => e.id)).toEqual([good.evidence_id]);
  });
});

describe('finding 5: integers beyond 2^53 after a restart', () => {
  it('submits a reloaded record holding a bigint', async () => {
    const dir = await directory();
    const evidence = await recorder.record({
      decision: DECISION, executed_capability: 'kv.write', outcome: 'success', execution_parameters: { modified_ns: 1760000000000000000 },
    });
    await new FileOutbox(dir).add({
      id: evidence.evidence_id, evidence, state: 'pending', attempts: 1, queued_at: '2026-10-10T00:00:00.000Z',
      next_attempt_at: null, last_error: null,
    });
    const bodies: string[] = [];
    const fetch = jest.fn(async (_url: unknown, init?: RequestInit) => {
      bodies.push(String(init?.body));
      return new Response(JSON.stringify({ status: 'recorded' }), { status: 201 });
    });
    const gm = new GenesisMeshClient({
      audience: 'TEST', baseUrl: 'http://na.test', fetch: fetch as unknown as typeof globalThis.fetch, outbox: new FileOutbox(dir),
    });
    expect((await gm.evidenceStore.flushPending()).admitted.map(e => e.id)).toEqual([evidence.evidence_id]);
    expect(bodies[0]).toContain('"modified_ns":1760000000000000000');
    expect(checkMetadataOnly({ n: 2n ** 60n })).toBeNull();
  });
  it('never names a local exception a network error', () => {
    expect(classifySubmissionError(new TypeError('Do not know how to serialize a BigInt')).failure)
      .toMatchObject({ status: 0, code: LOCAL_ERROR });
  });
});

describe('finding 6: the record outbox drains under the NA\'s rate limit', () => {
  it('halves its batches after a 429 and waits as long as Retry-After asks', async () => {
    const { store, gm } = client();
    const outbox = gm.evidenceStore.recordOutbox!;
    for (let n = 0; n < 150; n++) await outbox.add(recordOutboxEntry(await observe(n)));
    const throttled = () => Object.assign(new RateLimitError(), { retryAfterSeconds: 60 });
    const batch = jest.spyOn(store, 'submitObservations').mockImplementation(async records => {
      if (records.length > 60) throw throttled();
      return records.map((_, index) => ({ index, status: 'recorded' }) as ObservationBatchResult);
    });
    const before = Date.now();
    const first = await store.flushRecords();
    expect(first.admitted).toHaveLength(0);
    expect(Date.parse(first.pending[0]!.next_attempt_at!)).toBeGreaterThanOrEqual(before + 60_000);
    expect((await store.flushRecords()).admitted).toHaveLength(0);
    const second = await store.flushRecords({ ignoreBackoff: true });
    expect(second.admitted).toHaveLength(150);
    expect(batch.mock.calls.map(c => c[0].length)).toEqual([100, 50, 50, 50]);
  });
  it('reads Retry-After from the NA\'s answer', async () => {
    const fetch = jest.fn(async () => new Response(JSON.stringify({ error: { code: 'rate_limit_exceeded', message: 'slow down' } }),
      { status: 429, headers: { 'Retry-After': '60' } }));
    const t = new HttpTransport({ audience: 'TEST', baseUrl: 'http://na.test', fetch: fetch as unknown as typeof globalThis.fetch });
    const error = await t.publicPost('/evidence/observations', {}).catch(e => e) as RateLimitError;
    expect(error).toBeInstanceOf(RateLimitError);
    expect(error.retryAfterSeconds).toBe(60);
    expect(Date.parse(nextAttemptAt(1, error, 0))).toBe(60_000);
  });
  it('sends break-glass records before observations', async () => {
    const { store, gm } = client();
    const outbox = gm.evidenceStore.recordOutbox!;
    await outbox.add(recordOutboxEntry(await observe(1)));
    await outbox.add(recordOutboxEntry(await signBreakGlass(breakGlass, signer)));
    const order: string[] = [];
    jest.spyOn(store, 'submitObservations').mockImplementation(async records => {
      order.push('observations');
      return records.map((_, index) => ({ index, status: 'recorded' }) as ObservationBatchResult);
    });
    jest.spyOn(store, 'submitBreakGlass').mockImplementation(async () => { order.push('break_glass'); return recorded(); });
    expect((await store.flushRecords()).admitted).toHaveLength(2);
    expect(order).toEqual(['break_glass', 'observations']);
  });
  it('flushPending never answers with an action\'s partial drain', async () => {
    const { gm, store } = client({ outbox: new MemoryOutbox() });
    const sign = (resource_id: string, prior?: ExecutionEvidence) => recorder.record({
      decision: DECISION, executed_capability: 'c', outcome: 'success', resource_id, resource_action: 'rotate',
      prior_resource: prior ?? null,
    });
    const [other, a] = [await sign('kv:r1'), await sign('kv:r2')];
    const b = await sign('kv:r2', a);
    const submit = jest.spyOn(store, 'submit').mockRejectedValue(new NetworkError('offline'));
    await store.enqueue(other);
    await store.enqueue(a);
    let release!: () => void;
    const held = new Promise<void>(resolve => { release = resolve; });
    submit.mockImplementation(async evidence => {
      if (evidence === a || evidence.evidence_id === a.evidence_id) await held;
      return { status: 'recorded' } as never;
    });
    // b chains from a: enqueue drains a, then b, and nothing else.
    const inline = store.enqueue(b);
    await new Promise(resolve => setImmediate(resolve));
    const flushed = store.flushPending({ ignoreBackoff: true });
    release();
    expect((await inline).submission).toMatchObject({ status: 'recorded' });
    expect((await flushed).admitted.map(e => e.id)).toEqual([other.evidence_id]);
    expect(await gm.evidenceStore.outbox!.list()).toEqual([]);
  });
});

describe('finding 7: observations have deterministic IDs', () => {
  const finding: ReconciliationFinding = {
    resource_id: 'kv:prod/api-key', status: 'drifted', detail: 'cloud version 3, governed version 2',
    observed: { resource_id: 'kv:prod/api-key', exists: true, version: '3' }, recorded: null,
  };
  const options = { capability: 'secret.rotate', previousScanAt: new Date('2026-01-01T00:00:00Z'), scannedAt: new Date('2026-01-01T01:00:00Z') };
  it('signs a repeated scan\'s finding as the same record', async () => {
    const input = observationFromFinding(finding, options)!;
    const first = await observer.record(input);
    expect(await observer.record(observationFromFinding(finding, options)!)).toEqual(first);
    expect(first.observation_id).toBe(observationId('cloud-observer', 'reconciliation', input.source_event_id));
    expect(first.observation_id).toBe(createHash('sha256')
      .update(`cloud-observer\u0000reconciliation\u0000${input.source_event_id}`, 'utf-8').digest('hex'));
  });
  it('keeps an observation_id the caller gives', async () => {
    const record = await observer.record({ ...observation, changed_at: new Date(), source_event_id: 'e', observation_id: 'mine' });
    expect(record.observation_id).toBe('mine');
  });
});

describe('finding 8: resourceStates counts break-glass changes', () => {
  async function states(breakGlassAt: string) {
    const evidence = await recorder.record({
      decision: DECISION, executed_capability: 'c', outcome: 'success', resource_id: 'kv:v/s', resource_action: 'rotate',
      execution_parameters: { secret_version: 'v1' }, executed_at: new Date('2026-10-10T08:00:00Z'), prior_resource: null,
    });
    const glass = await signBreakGlass({
      ...breakGlass, resource_id: 'kv:v/s', executed_at: breakGlassAt, execution_parameters: { secret_version: 'v2' },
    }, signer);
    const event = (store_sequence: number, payload: object) => ({ entry: { store_sequence }, payload }) as unknown as EvidenceEvent;
    const store = new EvidenceStoreClient(new HttpTransport({ audience: 'TEST', baseUrl: 'http://unused' }));
    jest.spyOn(store, 'search').mockImplementation(async params => ({
      count: 1, next_after_sequence: null,
      entries: params?.entry_kind === 'execution' ? [event(5, evidence)] : params?.entry_kind === 'break_glass' ? [event(9, glass)] : [],
    }) as never);
    return { result: await store.resourceStates(), evidence, glass };
  }
  it('takes a later break-glass rotation as the resource\'s state', async () => {
    const { result, evidence, glass } = await states('2026-10-10T09:00:00Z');
    expect(result.get('kv:v/s')).toMatchObject({
      resource_sequence: 1, record_digest: executionDigest(evidence), last_success_parameters: { secret_version: 'v2' },
      last_break_glass_id: glass.break_glass_id, last_decision_id: 'd1',
    });
    expect(reconcileResources([{ resource_id: 'kv:v/s', exists: true, version: 'v2' }], result)[0]!.status).toBe('in_sync');
  });
  it('orders the changes by when they were made', async () => {
    const { result } = await states('2026-10-10T07:00:00Z');
    expect(result.get('kv:v/s')).toMatchObject({ last_success_parameters: { secret_version: 'v1' } });
    expect(result.get('kv:v/s')!.last_break_glass_id).toBeUndefined();
  });
});

describe('finding 10: keys named like built-ins', () => {
  const suite = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/conformance/out_of_band.json', import.meta.url)), 'utf-8'));
  const valid = suite.vectors.find((x: { id: string }) => x.id === 'export-valid').input;
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
  it('returns a verdict for a record whose key_id is `constructor`', () => {
    const events = parseExportLines(valid.lines);
    const seen = events.find(e => e.entry.entry_kind === 'observation')!;
    seen.payload = { ...seen.payload, extra: 1, signature: { key_id: 'constructor', sig: 'AAAA' } };
    const result = verifyEvidenceEvents(relink(events), {
      naPublicKeys: valid.na_public_keys, executorKeys: valid.executor_keys as ExecutorKeyInfo[],
    });
    expect(result.verified).toBe(false);
    expect(result.failures.map(f => f.reason)).toContain('payload_invalid');
  });
  it('refuses an envelope field named `constructor`', () => {
    const line = JSON.parse(valid.lines.trim().split('\n')[0]);
    expect(() => parseExportLines(JSON.stringify({ ...line, constructor: 1 }))).toThrow('envelope');
  });
});
