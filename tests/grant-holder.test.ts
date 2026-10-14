import { describe, expect, it, jest } from '@jest/globals';
import {
  GenesisMeshClient, GrantHolder, GrantRefusedError, GrantUnusableError, MemoryOutbox, grantRecordCanonical,
  grantUseDigest, pythonTimestamp, revocationFeedCanonical, seedSigner, signCanonical, verifyGrantUse,
  verifyTimeTokenRequest,
} from '../src/index.js';
import type {
  BreakGlassResult, CapabilityGrant, GrantFallbackResult, GrantHolderState, GrantUseResult, RecordOutboxEntry,
  SovereignRevocationFeed, TimeToken, TimeTokenRequest,
} from '../src/index.js';
import { generateTestKeyPair } from './helpers.js';

const NA = generateTestKeyPair();
const BEARER = generateTestKeyPair();
const OPERATOR = generateTestKeyPair();
const naSigner = seedSigner(NA.seedBase64, 'na-key');
const bearer = seedSigner(BEARER.seedBase64, 'device-key');
const START = Date.UTC(2026, 5, 1, 8, 0, 0);
const at = (seconds: number) => pythonTimestamp(new Date(START + seconds * 1000));

async function naSigned<T extends object>(record: T): Promise<T> {
  return { ...record, signature: await signCanonical(grantRecordCanonical(record), naSigner) };
}

/**
 * A Network Authority in memory: it issues time tokens for requests the
 * bearer key signs, admits uses and break-glass records, and serves its
 * revocation feed. `offline` makes every request fail as a stopped NA does.
 */
class FakeNA {
  offline = false;
  clock = START + 600_000;
  uses: unknown[] = [];
  breakGlass: unknown[] = [];
  tokenRefusal: string | null = null;
  /** Refuse the next use for good: the NA quarantines it. */
  quarantineNext: string | null = null;
  revokedGrants: string[] = [];
  feedSequence = 1;
  requests: string[] = [];

  fetch = (async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input));
    this.requests.push(`${init?.method ?? 'GET'} ${url.pathname}`);
    if (this.offline) throw new TypeError('fetch failed');
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    const reply = (status: number, value: unknown) => new Response(JSON.stringify(value), { status });
    switch (url.pathname) {
      case '/grants/time-tokens': {
        const request = body.request as TimeTokenRequest;
        if (!verifyTimeTokenRequest(request, BEARER.pubBase64)) return reply(422, { error: { code: 'time_token_request_invalid_signature', message: 'no' } });
        if (this.tokenRefusal) return reply(409, { error: { code: this.tokenRefusal, message: 'refused' } });
        const token = await naSigned<TimeToken>({
          time_token_id: `token-${request.use_sequence}-${this.clock}`, grant_id: request.grant_id,
          use_sequence: request.use_sequence,
          ...(request.use_head_digest ? { use_head_digest: request.use_head_digest } : {}),
          issued_at: pythonTimestamp(new Date(this.clock)), issuer_sovereign_id: 'sovereign-c', issued_by: 'na-key',
        });
        return reply(201, { time_token: token });
      }
      case '/evidence/grant-executions':
        if (this.quarantineNext) {
          const code = this.quarantineNext;
          this.quarantineNext = null;
          return reply(422, { error: { code, message: 'refused', details: { quarantine_id: 'q-1' } } });
        }
        this.uses.push(body.evidence);
        return reply(201, { status: 'recorded', entry: {}, entry_digest: 'd', payload: body.evidence, resource_sequence: this.uses.length });
      case '/evidence/break-glass':
        this.breakGlass.push(body.record);
        return reply(201, { status: 'recorded', entry: {}, entry_digest: 'd', payload: body.record });
      case '/sovereign-revocation-feed': {
        const feed: SovereignRevocationFeed = {
          feed_id: `feed-${this.feedSequence}`, issuer_sovereign_id: 'sovereign-c', sequence: this.feedSequence,
          issued_at: pythonTimestamp(new Date(this.clock)), revoked_attestation_ids: [], revocation_reasons: {},
          issued_by: 'na-key', signatures: [], revoked_grant_ids: this.revokedGrants,
        };
        feed.signatures = [await signCanonical(revocationFeedCanonical(feed), naSigner)];
        return reply(200, feed);
      }
      default:
        return reply(404, { error: { code: 'not_found', message: url.pathname } });
    }
  }) as typeof fetch;
}

async function setup(
  overrides: Partial<CapabilityGrant> = {},
  options: { persist?: (s: GrantHolderState) => void; resourcePrefix?: string } = {},
) {
  const na = new FakeNA();
  const grant = await naSigned<CapabilityGrant>({
    grant_id: 'grant-1', bearer_key_id: 'device-key', bearer_public_key: BEARER.pubBase64, bearer_sovereign_id: 'site-7',
    capabilities: ['secret.rotate'], basis_kind: 'attestation', basis_id: 'attestation-1', basis_digest: 'e'.repeat(64),
    requester_sovereign_id: 'vendor', provider_sovereign_id: 'sovereign-c', valid_from: at(0), valid_until: at(4 * 3600),
    max_uses: 3, max_uses_per_time_token: 2,
    parameter_envelope: {
      lifetime_days: {
        required: true, one_of: null, subset_of: null,
        number_range: { number_type: 'integer', minimum: 1, maximum: 60, exclusive_minimum: false, exclusive_maximum: false },
      },
    },
    basis_checks: [], policy_binding: { policies: [], policy_set_digest: 'f'.repeat(64), gate_outcomes: [], registry_gate_types: [] },
    issued_at: at(0), issuer_sovereign_id: 'sovereign-c', issued_by: 'na-key', ...overrides,
  });
  const timeToken = await naSigned<TimeToken>({
    time_token_id: 'token-0', grant_id: 'grant-1', use_sequence: 0, issued_at: at(0), issuer_sovereign_id: 'sovereign-c',
    issued_by: 'na-key',
  });
  const recordOutbox = new MemoryOutbox<RecordOutboxEntry>();
  const clients = new GenesisMeshClient({
    baseUrl: 'http://na', audience: 'TEST', signingKeyBase64: OPERATOR.seedBase64, keyId: 'ops', fetch: na.fetch, recordOutbox,
  });
  let clock = START + 600_000;
  const holder = new GrantHolder({
    clients, signer: bearer, naPublicKeys: [NA.pubBase64], grant, timeToken, now: () => new Date(clock), ...options,
  });
  const tick = (seconds: number) => { clock += seconds * 1000; na.clock = clock; };
  const verify = { operatorPublicKeys: [NA.pubBase64], expectedPolicies: [] };
  const fallback = { justification: 'the device is cut off and the key must rotate', verify };
  const rotate = (lifetime = 30) => ({
    capability: 'secret.rotate', request_parameters: { lifetime_days: lifetime }, resource_id: 'kv:site-7/api-key',
    resource_action: 'rotate' as const, fallback,
  });
  return { na, grant, timeToken, holder, clients, recordOutbox, tick, rotate };
}

describe('GrantHolder: acting within a grant offline (v1.6.0)', () => {
  it('acts with the NA stopped, keeps each use in the record outbox, and uploads them in order on reconnect', async () => {
    const x = await setup();
    x.na.offline = true;
    const action = jest.fn(async (_authority: unknown) => ({ value: 'rotated', execution_parameters: { version_id: 'v8' } }));
    const first = await x.holder.act(x.rotate(), action) as GrantUseResult<string>;
    expect(action).toHaveBeenCalledWith({ path: 'grant', grant: x.grant, use_sequence: 1 });
    expect(first).toMatchObject({ path: 'grant', value: 'rotated', queued: { state: 'pending', kind: 'grant_execution' } });
    expect(verifyGrantUse(first.use, BEARER.pubBase64)).toBe(true);
    expect(first.use).toMatchObject({ use_sequence: 1, executor_sovereign_id: 'site-7', time_token: x.timeToken });
    x.tick(60);
    const second = await x.holder.act(x.rotate(45), async () => ({ execution_parameters: { version_id: 'v9' } })) as GrantUseResult<unknown>;
    expect(second.use).toMatchObject({ use_sequence: 2, prev_use_digest: grantUseDigest(first.use) });
    expect(x.holder.state).toMatchObject({ uses: 2, head_digest: grantUseDigest(second.use) });
    expect(x.na.uses).toEqual([]);

    x.na.offline = false;
    const synced = await x.holder.sync();
    expect(synced).toMatchObject({ reachable: true, unusable: null, timeToken: { use_sequence: 2, use_head_digest: grantUseDigest(second.use) } });
    expect(synced.flushed?.admitted.map(e => e.id)).toEqual([first.use.use_id, second.use.use_id]);
    expect(x.na.uses).toEqual([first.use, second.use]);
    expect(await x.recordOutbox.list()).toEqual([]);
    // The next use cites the fresh token.
    const third = await x.holder.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(third.use.time_token.use_sequence).toBe(2);
    expect(third.submission?.resource_sequence).toBe(3);
  });

  it('refuses a request outside the grant, running nothing', async () => {
    const x = await setup();
    const action = jest.fn(async () => ({}));
    await expect(x.holder.act({ ...x.rotate(), capability: 'secret.delete' }, action)).rejects.toMatchObject({ code: 'grant_capability_mismatch' });
    await expect(x.holder.act(x.rotate(400), action)).rejects.toMatchObject({ code: 'grant_envelope_mismatch' });
    await expect(x.holder.act({ ...x.rotate(), request_parameters: { lifetime_days: 30, extra: 1 } }, action))
      .rejects.toBeInstanceOf(GrantRefusedError);
    await expect(x.holder.act({ capability: 'secret.rotate', request_parameters: { lifetime_days: 30 }, resource_id: 'r' }, action))
      .rejects.toThrow('go together');
    expect(action).not.toHaveBeenCalled();
    expect(x.holder.state.uses).toBe(0);
  });

  it('records a failed action as a failure use and rethrows', async () => {
    const x = await setup();
    x.na.offline = true;
    await expect(x.holder.act(x.rotate(), async () => { throw new Error('vault down'); })).rejects.toThrow('vault down');
    const [entry] = await x.recordOutbox.list();
    expect(entry!.record).toMatchObject({ outcome: 'failure', outcome_detail: 'action failed', use_sequence: 1 });
    expect(x.holder.state.uses).toBe(1);
  });

  it('records the outcome without metadata the secret guard refuses', async () => {
    const x = await setup();
    x.na.offline = true;
    const result = await x.holder.act(x.rotate(), async () => ({ execution_parameters: { version_id: 'v1', client_secret: 'no' } })) as GrantUseResult<unknown>;
    expect(result.dropped).toEqual(['client_secret']);
    expect(result.use.execution_parameters).toEqual({ version_id: 'v1' });
  });

  it('refuses request parameters carrying secret material before acting', async () => {
    const x = await setup({
      parameter_envelope: { token: { required: true, one_of: ['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln'], subset_of: null, number_range: null } },
    });
    const action = jest.fn(async () => ({}));
    await expect(x.holder.act({ capability: 'secret.rotate', request_parameters: { token: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln' } }, action))
      .rejects.toMatchObject({ code: 'grant_use_secret_material' });
    expect(action).not.toHaveBeenCalled();
  });

  it('never dates a use before its time token or the previous use', async () => {
    const x = await setup();
    x.tick(-900); // the holder's clock is 5 minutes behind the token
    x.na.offline = true;
    const result = await x.holder.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(result.use.executed_at).toBe(x.timeToken.issued_at);
  });

  it('asks for a fresh time token when its uses are spent, and falls back to break-glass when the NA cannot be reached', async () => {
    const x = await setup();
    await x.holder.act(x.rotate(), async () => ({}));
    await x.holder.act(x.rotate(), async () => ({}));
    // Two uses cite token 0; the third needs a new one, which the NA gives.
    const third = await x.holder.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(third.use.time_token.use_sequence).toBe(2);
    expect(x.na.requests.filter(r => r === 'POST /grants/time-tokens')).toHaveLength(1);
  });

  it('falls back to break-glass, naming the capability, when the time token is spent and the NA is down', async () => {
    const x = await setup({ max_uses_per_time_token: 1 });
    x.na.offline = true;
    await x.holder.act(x.rotate(), async () => ({}));
    const action = jest.fn(async (_authority: unknown) => ({ execution_parameters: { version_id: 'v2' } }));
    const result = await x.holder.act(x.rotate(), action) as GrantFallbackResult<unknown>;
    expect(result).toMatchObject({ path: 'break_glass', unusable: 'grant_time_token_exhausted' });
    expect(action).toHaveBeenCalledWith({ path: 'break_glass' });
    const broke = result.result as BreakGlassResult<unknown>;
    expect(broke.record).toMatchObject({
      capability: 'secret.rotate', attestation_id: 'attestation-1', executor_sovereign_id: 'site-7',
      request_parameters: { lifetime_days: 30 }, justification: 'the device is cut off and the key must rotate',
    });
    expect(x.holder.state.uses).toBe(1);
  });

  it('falls back to break-glass past the grant\'s end, and past its budget', async () => {
    const expired = await setup();
    expired.na.offline = true;
    expired.tick(4 * 3600);
    const late = await expired.holder.act(expired.rotate(), async () => ({})) as GrantFallbackResult<unknown>;
    expect(late).toMatchObject({ path: 'break_glass', unusable: 'grant_expired' });

    const spent = await setup({ max_uses: 1 });
    spent.na.offline = true;
    await spent.holder.act(spent.rotate(), async () => ({}));
    const over = await spent.holder.act(spent.rotate(), async () => ({})) as GrantFallbackResult<unknown>;
    expect(over).toMatchObject({ path: 'break_glass', unusable: 'grant_budget_exhausted' });
    expect((await spent.recordOutbox.list()).map(e => e.kind)).toEqual(['grant_execution', 'break_glass']);
  });

  it('throws GrantUnusableError without a fallback, and before the grant starts refuses outright', async () => {
    const x = await setup({ valid_from: at(3600), valid_until: at(7200) });
    await expect(x.holder.act({ ...x.rotate(), fallback: undefined }, async () => ({}))).rejects.toMatchObject({ code: 'grant_use_outside_validity' });
    const spent = await setup({ max_uses: 1 });
    spent.na.offline = true;
    await spent.holder.act(spent.rotate(), async () => ({}));
    await expect(spent.holder.act({ ...spent.rotate(), fallback: undefined }, async () => ({}))).rejects.toBeInstanceOf(GrantUnusableError);
  });

  it('refuses a revoked grant once its feed snapshot lists it, and never breaks through an NA that answers', async () => {
    const x = await setup();
    x.na.revokedGrants = ['grant-1'];
    expect(await x.holder.refreshRevocationFeed()).toBe(true);
    // The NA answers, but not with a decision this holder accepts (an operator key it does not hold): nothing runs.
    const action = jest.fn(async () => ({}));
    await expect(x.holder.act(x.rotate(), action)).rejects.toBeDefined();
    expect(action).not.toHaveBeenCalled();
    x.na.offline = true;
    const result = await x.holder.act(x.rotate(), async () => ({})) as GrantFallbackResult<unknown>;
    expect(result).toMatchObject({ path: 'break_glass', unusable: 'grant_revoked' });
  });

  it('keeps the newest verified feed, and refuses one the NA did not sign', async () => {
    const x = await setup();
    x.na.feedSequence = 5;
    await x.holder.refreshRevocationFeed();
    x.na.feedSequence = 4;
    x.na.revokedGrants = ['grant-1'];
    expect(await x.holder.refreshRevocationFeed()).toBe(false);
    expect(x.holder.state.revocation_feed?.sequence).toBe(5);
    const forged = { ...x.holder.state.revocation_feed!, revoked_grant_ids: [] };
    await expect(x.holder.updateRevocationFeed({ ...forged, sequence: 9 })).rejects.toMatchObject({ code: 'feed_invalid_signature' });
  });

  it('keeps the NA\'s answer that the grant has ended, and falls back with it later', async () => {
    const x = await setup();
    x.na.tokenRefusal = 'grant_expired';
    expect(await x.holder.sync()).toMatchObject({ reachable: true, unusable: 'grant_expired' });
    x.na.offline = true;
    const result = await x.holder.act(x.rotate(), async () => ({})) as GrantFallbackResult<unknown>;
    expect(result).toMatchObject({ path: 'break_glass', unusable: 'grant_expired' });
  });

  it('reports an unreachable NA from sync without throwing', async () => {
    const x = await setup();
    x.na.offline = true;
    expect(await x.holder.sync()).toEqual({ reachable: false, timeToken: null, unusable: null, flushed: null });
  });

  it('persists its state after every change and resumes from it', async () => {
    const saved: GrantHolderState[] = [];
    const x = await setup({}, { persist: s => { saved.push(s); } });
    x.na.offline = true;
    const first = await x.holder.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(saved.at(-1)).toMatchObject({ uses: 1, head_digest: grantUseDigest(first.use) });
    const resumed = new GrantHolder({
      clients: x.clients, signer: bearer, naPublicKeys: [NA.pubBase64], state: saved.at(-1)!, now: () => new Date(START + 700_000),
    });
    const second = await resumed.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(second.use).toMatchObject({ use_sequence: 2, prev_use_digest: grantUseDigest(first.use) });
  });

  it('refuses a grant, token or signer that is not the NA\'s or the bearer\'s', async () => {
    const x = await setup();
    const other = seedSigner(generateTestKeyPair().seedBase64, 'device-key');
    const options = { clients: x.clients, naPublicKeys: [NA.pubBase64], grant: x.grant, timeToken: x.timeToken };
    expect(() => new GrantHolder({ ...options, signer: seedSigner(BEARER.seedBase64, 'other') })).toThrow(GrantRefusedError);
    expect(() => new GrantHolder({ ...options, signer: bearer, naPublicKeys: [BEARER.pubBase64] })).toThrow('not signed by the NA');
    expect(() => new GrantHolder({ ...options, signer: bearer, timeToken: { ...x.timeToken, use_sequence: 1 } }))
      .toThrow(GrantRefusedError);
    const impostor = new GrantHolder({ ...options, signer: other });
    await expect(impostor.act(x.rotate(), async () => ({}))).rejects.toMatchObject({ code: 'grant_bearer_mismatch' });
    expect(() => new GrantHolder({ ...options, signer: bearer, clients: new GenesisMeshClient({ baseUrl: 'http://na' }) }))
      .toThrow('record outbox');
  });

  it('keeps a use the NA quarantines in its chain: the next use follows it and is judged on its own', async () => {
    const x = await setup();
    x.na.quarantineNext = 'grant_use_outside_validity';
    const first = await x.holder.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(first.queued).toMatchObject({ state: 'dead_letter', last_error: { code: 'grant_use_outside_validity' } });
    const second = await x.holder.act(x.rotate(), async () => ({})) as GrantUseResult<unknown>;
    expect(second.use).toMatchObject({ use_sequence: 2, prev_use_digest: grantUseDigest(first.use) });
    expect(second.submission?.status).toBe('recorded');
    expect(x.holder.state.uses).toBe(2);
  });

  it('refuses offline a use outside the bearer key resource prefix, or without a resource', async () => {
    const x = await setup({}, { resourcePrefix: 'kv:site-7/' });
    const action = jest.fn(async () => ({}));
    await expect(x.holder.act({ ...x.rotate(), resource_id: 'kv:site-8/api-key' }, action)).rejects.toMatchObject({ code: 'grant_use_out_of_scope' });
    await expect(x.holder.act({ capability: 'secret.rotate', request_parameters: { lifetime_days: 30 } }, action))
      .rejects.toMatchObject({ code: 'grant_use_out_of_scope' });
    expect(action).not.toHaveBeenCalled();
    expect((await x.holder.act(x.rotate(), action)).path).toBe('grant');
  });

  it('runs two uses one after the other, never at one place in the chain', async () => {
    const x = await setup();
    x.na.offline = true;
    const [a, b] = await Promise.all([x.holder.act(x.rotate(), async () => ({})), x.holder.act(x.rotate(), async () => ({}))]) as GrantUseResult<unknown>[];
    expect([a!.use.use_sequence, b!.use.use_sequence]).toEqual([1, 2]);
  });
});
