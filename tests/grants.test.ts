import { describe, expect, it, jest } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  FileRecordOutbox, GenesisMeshClient, GrantRecordError, MemoryOutbox, NetworkError, PREDECESSOR_DEAD_LETTERED,
  RECORD_PERMANENT_REFUSALS, StrictJsonError, ValidationError, canonicalJson, checkCompleteness, envelopeParameter,
  envelopeProblem, grantDigest, grantRecordCanonical, grantUseDigest, inRange, judgementState, normalizeNumber,
  parseExportLines, parseJson, pythonTimestamp, recordOutboxEntry, renderReport, revocationFeedCanonical, scalarEquals,
  seedSigner, signCanonical, signGrantUse, signTimeTokenRequest, useProblem, verifyCapabilityGrant, verifyEvidenceEvents,
  verifyGrantRevocation, verifyGrantUse, verifyRevocationFeedSignature, verifyTimeToken, verifyTimeTokenRequest,
} from '../src/index.js';
import type {
  CapabilityGrant, EvidenceEvent, ExecutorKeyInfo, GrantExecutionEvidence, GrantRevocationRecord, NumericRange,
  RecordOutboxEntry, RecordSubmission, SovereignRevocationFeed, TimeToken,
} from '../src/index.js';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateTestKeyPair, mockFetch } from './helpers.js';
import { FEED_OMITTED_WHEN_ABSENT } from '../src/canonical.js';
import { CANONICAL_REGISTRY } from '../src/canonical-registry.js';

const NA = generateTestKeyPair();
const BEARER = generateTestKeyPair();
const naSigner = seedSigner(NA.seedBase64, 'na-key');
const bearerSigner = seedSigner(BEARER.seedBase64, 'device-key');
const at = (offsetSeconds: number) => pythonTimestamp(new Date(Date.UTC(2026, 5, 1, 8, 0, 0) + offsetSeconds * 1000));

async function naSigned<T extends object>(record: T): Promise<T> {
  return { ...record, signature: await signCanonical(grantRecordCanonical(record), naSigner) };
}

function grantBody(overrides: Partial<CapabilityGrant> = {}): CapabilityGrant {
  return {
    grant_id: '00000000-0000-4000-8000-000000000010', bearer_key_id: 'device-key', bearer_public_key: BEARER.pubBase64,
    bearer_sovereign_id: 'device-b', capabilities: ['secret.rotate'], basis_kind: 'attestation',
    basis_id: '00000000-0000-4000-8000-000000000001', basis_digest: 'e'.repeat(64), requester_sovereign_id: 'vendor',
    provider_sovereign_id: 'sovereign-c', valid_from: at(0), valid_until: at(4 * 3600), max_uses: 3,
    max_uses_per_time_token: 2,
    parameter_envelope: {
      lifetime_days: {
        required: true, one_of: null, subset_of: null,
        number_range: { number_type: 'integer', minimum: 1, maximum: 90, exclusive_minimum: false, exclusive_maximum: false },
      },
    },
    basis_checks: [], policy_binding: { policies: [], policy_set_digest: 'f'.repeat(64), gate_outcomes: [], registry_gate_types: [] },
    issued_at: at(0), issuer_sovereign_id: 'sovereign-c', issued_by: 'na-key', ...overrides,
  };
}

async function world() {
  const grant = await naSigned(grantBody());
  const token = await naSigned<TimeToken>({
    time_token_id: '00000000-0000-4000-8000-000000000030', grant_id: grant.grant_id, use_sequence: 0, issued_at: at(0),
    issuer_sovereign_id: 'sovereign-c', issued_by: 'na-key',
  });
  const use = await signGrantUse({
    grant, use_sequence: 1, previous: null, capability: 'secret.rotate', request_parameters: { lifetime_days: 30 },
    resource_id: 'kv:vault/api-key', resource_action: 'rotate', executed_at: at(300), time_token: token,
    outcome: 'success', execution_parameters: { version_id: 'v1' },
  }, bearerSigner);
  return { grant, token, use };
}

describe('numbers and envelopes (v1.6.0)', () => {
  it('reads an integral number as an integer within 64 bits, exactly', () => {
    expect(normalizeNumber(5)).toBe(5);
    expect(normalizeNumber(2 ** 60)).toBe(2n ** 60n);
    expect(normalizeNumber(2n ** 64n - 1n)).toBe(2n ** 64n - 1n);
    expect(normalizeNumber(1.5)).toBe(1.5);
    expect(() => normalizeNumber(2n ** 64n)).toThrow('64 bits');
    expect(() => normalizeNumber(true)).toThrow('number');
    expect(() => normalizeNumber(Infinity)).toThrow('finite');
  });

  it('compares exactly: an integer range up to 2^53 + 1 is above 2^53', () => {
    const range: NumericRange = {
      number_type: 'integer', minimum: 1, maximum: 2n ** 53n + 1n, exclusive_minimum: false, exclusive_maximum: false,
    };
    expect(inRange(2n ** 53n + 1n, range)).toBe(true);
    expect(inRange(2n ** 53n + 2n, range)).toBe(false);
    expect(inRange(2 ** 53, { ...range, maximum: 2n ** 53n, exclusive_maximum: true })).toBe(false);
    expect(inRange(true, range)).toBe(false);
    expect(inRange(2.5, range)).toBe(false);
    expect(inRange(2.5, { ...range, number_type: 'number' })).toBe(true);
  });

  it('compares sets type-strictly: true is not 1, "1" is not 1, 1 is 1.0', () => {
    expect(scalarEquals(true, 1)).toBe(false);
    expect(scalarEquals('1', 1)).toBe(false);
    expect(scalarEquals(1, parseJson('1.0'))).toBe(true);
    expect(scalarEquals(2n ** 60n, 2 ** 60)).toBe(true);
    expect(scalarEquals(null, null)).toBe(true);
  });

  it('normalizes a parameter and names why one is refused', () => {
    expect(envelopeParameter({ one_of: ['a', 5, null] })).toEqual({ required: true, one_of: ['a', 5, null], subset_of: null, number_range: null });
    expect(() => envelopeParameter({ one_of: ['a'], extra: 1 })).toThrow(GrantRecordError);
    expect(() => envelopeParameter({ number_range: { number_type: 'number', minimum: 2, maximum: 2, exclusive_minimum: true } }))
      .toThrow('holds no number');
    expect(() => envelopeParameter({ subset_of: ['a', 'a'] })).toThrow('repeats');
    try {
      envelopeParameter({});
    } catch (err) {
      expect(err).toMatchObject({ code: 'invalid_grant_envelope' });
    }
  });

  it('keeps the envelope closed', () => {
    const envelope = { n: { number_range: { number_type: 'integer', minimum: 1, maximum: 9 } } };
    expect(envelopeProblem(envelope, { n: 3 })).toBeNull();
    expect(envelopeProblem(envelope, { n: 3, x: 1 })).toBe('request_parameters.x is not in the envelope');
    expect(envelopeProblem(envelope, {})).toBe('request_parameters.n is required');
    expect(envelopeProblem(envelope, [])).toBe('request_parameters is not an object');
  });
});

describe('the signed records (v1.6.0)', () => {
  it('verifies a grant, a time token, a use and a revocation, and refuses each altered', async () => {
    const { grant, token, use } = await world();
    expect(verifyCapabilityGrant(grant, [NA.pubBase64])).toBe(true);
    expect(verifyCapabilityGrant({ ...grant, max_uses: 4 }, [NA.pubBase64])).toBe(false);
    expect(verifyCapabilityGrant({ ...grant, extra: 1 } as never, [NA.pubBase64])).toBe(false);
    expect(verifyCapabilityGrant(grant, [BEARER.pubBase64])).toBe(false);
    expect(verifyTimeToken(token, [NA.pubBase64])).toBe(true);
    expect(verifyTimeToken({ ...token, use_sequence: 1 }, [NA.pubBase64])).toBe(false);
    expect(verifyGrantUse(use, BEARER.pubBase64)).toBe(true);
    expect(verifyGrantUse({ ...use, capability: 'secret.read' }, BEARER.pubBase64)).toBe(false);
    expect(use.grant_digest).toBe(grantDigest(grant));
    expect(use).not.toHaveProperty('prev_use_digest');
    expect(use.time_token).not.toHaveProperty('use_head_digest');
    const revocation = await naSigned<GrantRevocationRecord>({
      revocation_id: 'r-1', grant_id: grant.grant_id, grant_digest: grantDigest(grant), reason: 'operator',
      revoked_at: at(600), issuer_sovereign_id: 'sovereign-c', issued_by: 'na-key',
    });
    expect(verifyGrantRevocation(revocation, [NA.pubBase64])).toBe(true);
    expect(verifyGrantRevocation({ ...revocation, reason: 'policy_activated' }, [NA.pubBase64])).toBe(false);
  });

  it('refuses a grant valid longer than 24 hours, even signed', async () => {
    const grant = await naSigned(grantBody({ valid_until: at(24 * 3600 + 1) }));
    expect(verifyCapabilityGrant(grant, [NA.pubBase64])).toBe(false);
  });

  it('signs a time token request in its exact form, with the head only after a use', async () => {
    const first = await signTimeTokenRequest({ grant_id: 'g', use_sequence: 0, requested_at: at(0) }, bearerSigner);
    expect(Object.keys(first)).toEqual(['grant_id', 'use_sequence', 'requested_at', 'signature']);
    expect(verifyTimeTokenRequest(first, BEARER.pubBase64)).toBe(true);
    await expect(signTimeTokenRequest({ grant_id: 'g', use_sequence: 1, requested_at: at(0) }, bearerSigner))
      .rejects.toMatchObject({ code: 'time_token_request_malformed' });
    const later = await signTimeTokenRequest({ grant_id: 'g', use_sequence: 1, use_head_digest: 'a'.repeat(64) }, bearerSigner);
    expect(verifyTimeTokenRequest(later, BEARER.pubBase64)).toBe(true);
  });

  it('refuses a use before signing as the NA would: malformed, secret material, unreadable JSON', async () => {
    const { grant, token, use } = await world();
    const input = {
      grant, use_sequence: 2, previous: use, capability: 'secret.rotate', request_parameters: { lifetime_days: 30 },
      executed_at: at(400), time_token: token, outcome: 'success' as const,
    };
    const second = await signGrantUse(input, bearerSigner);
    expect(second.prev_use_digest).toBe(grantUseDigest(use));
    await expect(signGrantUse({ ...input, previous: null }, bearerSigner)).rejects.toMatchObject({ code: 'grant_use_malformed' });
    await expect(signGrantUse({ ...input, execution_parameters: { client_secret: 'x' } }, bearerSigner))
      .rejects.toMatchObject({ code: 'grant_use_secret_material' });
    await expect(signGrantUse({ ...input, request_parameters: { password: 'x' } }, bearerSigner))
      .rejects.toMatchObject({ code: 'grant_use_secret_material' });
    await expect(signGrantUse({ ...input, execution_parameters: { n: 2n ** 64n } }, bearerSigner)).rejects.toBeInstanceOf(StrictJsonError);
  });

  it('checks a use offline as the NA does, naming the first rule it breaks', async () => {
    const { grant, token, use } = await world();
    const check = { grant, previous: null, tokenHead: null, tokenKeys: [NA.pubBase64], revokedAt: null, recordedAt: at(300) };
    expect(useProblem(use, check)).toBeNull();
    expect(useProblem(use, { ...check, tokenKeys: [BEARER.pubBase64] })?.code).toBe('grant_time_token_invalid');
    expect(useProblem(use, { ...check, revokedAt: at(300) })?.code).toBe('grant_revoked');
    expect(useProblem(use, { ...check, recordedAt: at(-1) })?.code).toBe('grant_use_in_future');
    expect(useProblem({ ...use, capability: 'x' }, { ...check, revokedAt: at(0) })?.code).toBe('grant_capability_mismatch');
    expect(useProblem({ ...use, executed_at: at(-1) }, { ...check, grant: null })?.code).toBe('grant_use_before_time_token');
    expect(useProblem({ ...use, time_token: token }, check)).toBeNull();
  });
});

describe('the revocation feed (v1.6.0)', () => {
  async function feed(grants?: string[]): Promise<SovereignRevocationFeed> {
    const body: SovereignRevocationFeed = {
      feed_id: 'f-1', issuer_sovereign_id: 'sovereign-c', sequence: 3, issued_at: at(0),
      revoked_attestation_ids: [], revocation_reasons: {}, issued_by: 'na-key', signatures: [],
      ...(grants ? { revoked_grant_ids: grants } : {}),
    };
    return { ...body, signatures: [await signCanonical(revocationFeedCanonical(body), naSigner)] };
  }

  it('verifies a feed listing revoked grants, and one in its 1.5 form', async () => {
    expect(verifyRevocationFeedSignature(await feed(['g-1', 'g-2']), [NA.pubBase64])).toBe(true);
    expect(verifyRevocationFeedSignature(await feed(), [NA.pubBase64])).toBe(true);
    const listed = await feed(['g-1']);
    expect(verifyRevocationFeedSignature({ ...listed, revoked_grant_ids: [] }, [NA.pubBase64])).toBe(false);
  });

  it('leaves revoked_grant_ids out of the signed form when absent, as the registry says', async () => {
    expect([...FEED_OMITTED_WHEN_ABSENT]).toEqual(CANONICAL_REGISTRY.models['SovereignRevocationFeed']!.omit_when_none);
    const without = await feed();
    expect(revocationFeedCanonical({ ...without, revoked_grant_ids: null } as never)).toBe(revocationFeedCanonical(without));
    expect(revocationFeedCanonical(without)).not.toContain('revoked_grant_ids');
  });
});

describe('exports, packs and reports holding grants (v1.6.0)', () => {
  const raw = readFileSync(fileURLToPath(new URL('./fixtures/conformance/grants.json', import.meta.url)), 'utf-8')
    .replace('18446744073709551616', '0');
  const vectors = (parseJson(raw) as { vectors: Array<{ id: string; input: Record<string, unknown> }> }).vectors;
  const vector = vectors.find(v => v.id === 'export-valid')!;
  const events = parseExportLines(vector.input['lines'] as string);
  const options = { naPublicKeys: vector.input['na_public_keys'] as string[], executorKeys: vector.input['executor_keys'] as ExecutorKeyInfo[] };

  it('names a grant a pack range does not hold or cite: cited_record_missing', () => {
    const range = events.slice(1, 3);
    const missing = verifyEvidenceEvents(range, { ...options, prior: [] });
    expect(missing.failures.map(f => [f.store_sequence, f.reason, f.detail])).toEqual([
      [2, 'cited_record_missing', 'grant 00000000-0000-4000-8000-000000000010'],
      [3, 'cited_record_missing', 'grant 00000000-0000-4000-8000-000000000010'],
    ]);
    const cited = verifyEvidenceEvents(range, { ...options, prior: events.slice(0, 1) });
    expect(cited.failures).toEqual([]);
    expect(cited).toMatchObject({ grant_executions: 2 });
    expect(cited.grants).toBeUndefined();
  });

  it('checks a use cited outside the run for its time token only', () => {
    const other = parseExportLines(vectors.find(v => v.id === 'export-time-token-not-the-nas')!.input['lines'] as string);
    const result = verifyEvidenceEvents([], { ...options, prior: other });
    expect(result.failures.map(f => [f.store_sequence, f.reason])).toEqual([[2, 'grant_time_token_invalid']]);
    expect(verifyEvidenceEvents([], { ...options, prior: events.slice(0, 3) }).failures).toEqual([]);
  });

  it('reports uses as changes governed by the grant, and grants and revocations in their own sections', () => {
    const report = renderReport({
      manifest: {
        pack_id: 'p', sovereign_id: 'sovereign-c', from_sequence: 1, through_sequence: 5, start_anchor_sequence: null,
        end_anchor_sequence: 1, created_at: '2026-06-01T09:00:00Z', requested_by: null, period_from: null, period_until: null,
      },
      entries: events, checks: { verified: true, failures: [], counts: { grants: 1 } },
    });
    expect(report).toContain('| 2 | grant_execution | kv:vault/api-key | rotate | 2026-06-01T08:02:00Z | grant | recorded | device-b |');
    expect(report).toContain('## Grants\n\n| Entry | Grant | Bearer | Capabilities | Valid from | Valid until | Budget |');
    expect(report).toContain('| 1 | 00000000-0000-4000-8000-000000000010 | device-b | ["secret.rotate"] |');
    expect(report).toContain('## Grant revocations\n\n| Entry | Grant | Reason | Revoked at |');
    // A pack without grants renders as in 1.5.
    const before = renderReport({
      manifest: {
        pack_id: 'p', sovereign_id: 's', from_sequence: 4, through_sequence: 4, start_anchor_sequence: null,
        end_anchor_sequence: 1, created_at: '2026-06-01T09:00:00Z', requested_by: null, period_from: null, period_until: null,
      },
      entries: events.slice(3, 4), checks: { verified: true },
    });
    expect(before).not.toContain('## Grants');
    expect(before.endsWith('## Key successions and archives\n\nNone.\n')).toBe(true);
  });

  it('matches a change from an outside log to a grant use', () => {
    const report = checkCompleteness([{
      index: 1, resource_id: 'kv:vault/api-key', action: 'rotate', changed_at: '2026-06-01T08:02:00Z',
    }], events.slice(1, 2), events.slice(0, 1), { period: ['2026-06-01T08:00:00Z', '2026-06-01T09:00:00Z'] });
    expect(report.pairs).toEqual([expect.objectContaining({ change: 1, kind: 'grant_execution', record_id: '00000000-0000-4000-8000-000000000101' })]);
    expect(report.complete).toBe(true);
  });

  it('enters a change matched to a grant use as matched', () => {
    expect(judgementState('allow', 'grant')).toBe('matched');
    expect(judgementState('deny', 'grant')).toBe('judged_denied');
  });
});

describe('grant uses in the record outbox (v1.6.0)', () => {
  const recorded = { status: 'recorded', entry: {}, entry_digest: 'd', payload: {}, resource_sequence: 7 } as unknown as RecordSubmission;

  it('keeps a use as kind grant_execution, also in the file outbox', async () => {
    const { use } = await world();
    const entry = recordOutboxEntry(use);
    expect(entry).toMatchObject({ kind: 'grant_execution', id: use.use_id, state: 'pending' });
    const dir = await mkdtemp(join(tmpdir(), 'gm-grants-'));
    try {
      await new FileRecordOutbox(dir).add(entry);
      expect((await new FileRecordOutbox(dir).list())[0]).toEqual(entry);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  it('submits a use to /evidence/grant-executions, after break-glass records', async () => {
    const { use } = await world();
    const fetch = mockFetch({ status: 201, body: recorded });
    const outbox = new MemoryOutbox<RecordOutboxEntry>();
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://na', fetch: fetch as unknown as typeof globalThis.fetch, recordOutbox: outbox });
    await outbox.add(recordOutboxEntry(use));
    await outbox.add(recordOutboxEntry({ break_glass_id: 'b' } as never));
    const flushed = await gm.evidenceStore.flushRecords();
    expect(flushed.admitted.map(e => e.kind)).toEqual(['break_glass', 'grant_execution']);
    const urls = fetch.mock.calls.map(c => String(c[0]));
    expect(urls.slice(0, 2)).toEqual(['http://na/evidence/break-glass', 'http://na/evidence/grant-executions']);
    expect(JSON.parse(String((fetch.mock.calls[1] as [string, RequestInit])[1].body))).toEqual({ evidence: JSON.parse(canonicalJson(use)) });
  });

  it('dead-letters a use the NA refuses for good, retries a chain gap, and dead-letters a gap behind a dead letter', async () => {
    const { grant, token, use } = await world();
    const second = await signGrantUse({
      grant, use_sequence: 2, previous: use, capability: 'secret.rotate', request_parameters: { lifetime_days: 30 },
      executed_at: at(400), time_token: token, outcome: 'success',
    }, bearerSigner);
    expect(RECORD_PERMANENT_REFUSALS.has('grant_envelope_mismatch')).toBe(true);
    expect(RECORD_PERMANENT_REFUSALS.has('grant_use_chain_gap')).toBe(false);
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://na', recordOutbox: new MemoryOutbox<RecordOutboxEntry>() });
    const http = (gm.evidenceStore as unknown as { http: { publicPost: (...a: unknown[]) => Promise<unknown> } }).http;
    const post = jest.spyOn(http, 'publicPost')
      .mockRejectedValueOnce(new ValidationError('outside', 'grant_use_chain_gap'))
      .mockRejectedValueOnce(new ValidationError('refused', 'grant_envelope_mismatch'))
      .mockRejectedValueOnce(new ValidationError('gap', 'grant_use_chain_gap'));
    expect((await gm.evidenceStore.enqueueRecord(second)).queued).toMatchObject({ state: 'pending', last_error: { code: 'grant_use_chain_gap' } });
    expect((await gm.evidenceStore.enqueueRecord(use)).queued).toMatchObject({ state: 'dead_letter', last_error: { code: 'grant_envelope_mismatch' } });
    const flushed = await gm.evidenceStore.flushRecords({ ignoreBackoff: true });
    expect(flushed.dead_lettered.map(e => [e.id, e.last_error?.code])).toEqual([[second.use_id, PREDECESSOR_DEAD_LETTERED]]);
    expect(post).toHaveBeenCalledTimes(3);
  });

  it('retries a use while the NA is unreachable', async () => {
    const { use } = await world();
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://na', recordOutbox: new MemoryOutbox<RecordOutboxEntry>() });
    const http = (gm.evidenceStore as unknown as { http: { publicPost: (...a: unknown[]) => Promise<unknown> } }).http;
    jest.spyOn(http, 'publicPost').mockRejectedValueOnce(new NetworkError('down'));
    expect((await gm.evidenceStore.enqueueRecord(use)).queued?.state).toBe('pending');
  });
});

describe('GrantsClient routes (v1.6.0)', () => {
  const key = generateTestKeyPair();
  const client = (body: unknown, status = 200) => {
    const fetch = mockFetch({ status, body });
    return { fetch, gm: new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://na/', signingKeyBase64: key.seedBase64, keyId: 'ops', fetch: fetch as unknown as typeof globalThis.fetch }) };
  };
  const sent = (fetch: jest.Mock) => {
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    const headers = init.headers as Record<string, string>;
    return { url, method: init.method, admin: headers['X-Admin-Signature'] !== undefined, body: init.body === undefined ? undefined : JSON.parse(String(init.body)) };
  };

  it.each([
    ['issueGrant', 'POST', 'http://na/admin/grants', true, (gm: GenesisMeshClient) => gm.grants.issueGrant({
      bearer_key_id: 'k', capabilities: ['c'], attestation_id: 'a', valid_until: new Date(Date.UTC(2026, 5, 1, 12)), max_uses: 3,
      parameter_envelope: { n: { number_range: { number_type: 'integer', minimum: 1, maximum: 9 } } },
    }), { bearer_key_id: 'k', capabilities: ['c'], attestation_id: 'a', valid_until: '2026-06-01T12:00:00.000Z', max_uses: 3,
      parameter_envelope: { n: { number_range: { number_type: 'integer', minimum: 1, maximum: 9 } } } }],
    ['listGrants', 'GET', 'http://na/admin/grants?status=revoked&limit=10', true, (gm: GenesisMeshClient) => gm.grants.listGrants({ status: 'revoked', limit: 10 }), undefined],
    ['getGrant', 'GET', 'http://na/admin/grants/g%2F1', true, (gm: GenesisMeshClient) => gm.grants.getGrant('g/1'), undefined],
    ['revokeGrant', 'POST', 'http://na/admin/grants/g%2F1/revoke', true, (gm: GenesisMeshClient) => gm.grants.revokeGrant('g/1', 'lost'), { reason: 'lost' }],
    ['submitGrantUse', 'POST', 'http://na/evidence/grant-executions', false, (gm: GenesisMeshClient) => gm.grants.submitGrantUse({ use_id: 'u' } as GrantExecutionEvidence), { evidence: { use_id: 'u' } }],
  ] as const)('%s', async (_name, method, url, admin, call, body) => {
    const { fetch, gm } = client({ ok: true });
    await call(gm);
    expect(sent(fetch)).toEqual({ url, method, admin, body });
  });

  it('requestTimeToken signs the request with the bearer key and returns the token', async () => {
    const { fetch, gm } = client({ time_token: { time_token_id: 't' } }, 201);
    expect(await gm.grants.requestTimeToken({ grant_id: 'g', use_sequence: 0 }, bearerSigner)).toEqual({ time_token_id: 't' });
    const request = sent(fetch);
    expect(request).toMatchObject({ url: 'http://na/grants/time-tokens', method: 'POST', admin: false });
    expect(verifyTimeTokenRequest(request.body.request, BEARER.pubBase64)).toBe(true);
    await expect(gm.grants.requestTimeToken({ grant_id: 'g', use_sequence: 0 })).rejects.toThrow('signer');
  });
});
