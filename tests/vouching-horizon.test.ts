import { describe, expect, it } from '@jest/globals';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  GenesisMeshClient, GrantHolder, GrantRefusedError, MemoryOutbox, NAKeyHistory, SUCCESSION_VOUCHING_GRACE_SECONDS,
  grantRecordCanonical, naKeysVouchingAt, parseJson, pythonTimestamp, recordOutlivesKey, revocationFeedCanonical,
  seedSigner, signCanonical, verifyAttestationSignature, verifyCapabilityGrant, verifyKeyHistory,
  verifyKeyHistoryView, verifyRevocationFeedSignature, verifyTreatySignature,
} from '../src/index.js';
import type {
  CapabilityGrant, KeyHistoryView, NAKey, RecordOutboxEntry,
  SovereignRevocationFeed, TimeToken,
} from '../src/index.js';
import { generateTestKeyPair } from './helpers.js';

/**
 * The vouching horizon (1.8.0) in this SDK: a record of an NA key that has
 * ended vouches for the present only until that key's end, the 300-second
 * hand-over and the grace (24 hours at most). Judged at its own time, a record
 * is unchanged. The `vouching` conformance suite pins the verdicts; these tests
 * pin the helpers, the verifiers' `now` option and the grant holder.
 */

interface Vector {
  id: string;
  model: string;
  input: { genesis: unknown; successions: unknown[]; root_public_key: string; record: Record<string, unknown>; now: string };
}
const suite = parseJson(readFileSync(fileURLToPath(new URL('./fixtures/conformance/vouching.json', import.meta.url)),
  'utf-8')) as { vectors: Vector[] };
const vector = (id: string) => suite.vectors.find(v => v.id === id)!;

function historyOf(v: Vector): NAKeyHistory {
  const result = verifyKeyHistory(v.input.genesis, v.input.successions, v.input.root_public_key);
  if (result.history === null) throw new Error(JSON.stringify(result.failures));
  return result.history;
}

const SUCCEEDED = Date.UTC(2026, 0, 11);
const iso = (ms: number) => pythonTimestamp(new Date(ms));

/** Two keys: the old one succeeded at SUCCEEDED, the new one from then on, with a one-hour grace. */
function twoKeys(oldKey: string, newKey: string, graceSeconds = 3600): NAKeyHistory {
  const keys: NAKey[] = [
    { key_sequence: 1, key_id: 'na-1', public_key: oldKey, valid_from: null, succeeded_at: iso(SUCCEEDED), valid_to: null,
      valid_to_enforced: false },
    { key_sequence: 2, key_id: 'na-2', public_key: newKey, valid_from: iso(SUCCEEDED), succeeded_at: null,
      valid_to: iso(SUCCEEDED + 365 * 86_400_000), valid_to_enforced: true },
  ];
  return new NAKeyHistory('TEST', null, keys, []).withVouchingGrace(graceSeconds);
}

describe('the horizon helpers', () => {
  const h = twoKeys('old', 'new');
  const horizon = SUCCEEDED + 300_000 + 3_600_000;

  it('a record of the old key vouches until its end, the hand-over and the grace', () => {
    expect(h.vouchesUntilMicros('old')).toBe(horizon * 1000);
    expect(recordOutlivesKey(h, 'old', new Date(horizon - 1))).toBe(false);
    expect(recordOutlivesKey(h, 'old', new Date(horizon))).toBe(true);
    // The new key ends at its enforced valid_to; a key with neither a succession nor an enforced
    // end (the genesis key while current), a key outside the history and a list of keys have no end.
    expect(h.vouchesUntilMicros('new')).toBe((SUCCEEDED + 365 * 86_400_000 + 300_000 + 3_600_000) * 1000);
    expect(recordOutlivesKey(h, 'new', new Date(horizon + 1e9))).toBe(false);
    expect(NAKeyHistory.ofKeys(['genesis']).vouchesUntilMicros('genesis')).toBeNull();
    expect(recordOutlivesKey(h, 'stranger', new Date(horizon))).toBe(false);
    expect(recordOutlivesKey(['old'], 'old', new Date(horizon))).toBe(false);
  });

  it('naKeysVouchingAt drops the keys whose horizon has passed', () => {
    const before = iso(SUCCEEDED - 1000);
    expect(naKeysVouchingAt(h, before, new Date(horizon - 1))).toEqual(['old']);
    expect(naKeysVouchingAt(h, before, new Date(horizon))).toEqual([]);
  });

  it('the grace can only be shortened', () => {
    expect(twoKeys('a', 'b', SUCCESSION_VOUCHING_GRACE_SECONDS).withVouchingGrace(10 * 86_400).vouching_grace_seconds)
      .toBe(SUCCESSION_VOUCHING_GRACE_SECONDS);
    expect(h.withVouchingGrace(60).vouching_grace_seconds).toBe(60);
    expect(h.withVouchingGrace(7200).vouching_grace_seconds).toBe(3600);
    expect(h.withVouchingGrace(-5).vouching_grace_seconds).toBe(0);
    expect(h.withVouchingGrace(null)).toBe(h);
    expect(new NAKeyHistory('TEST', null, []).vouching_grace_seconds).toBe(SUCCESSION_VOUCHING_GRACE_SECONDS);
  });

  it("the NA's unsigned hint in the key history view only shortens the grace", () => {
    const v = vector('attestation-old-key-within-grace');
    const view = (hint: unknown) => ({ genesis: v.input.genesis, successions: v.input.successions,
      vouching_grace_seconds: hint }) as unknown as KeyHistoryView;
    const grace = (hint: unknown) => verifyKeyHistoryView(view(hint), v.input.root_public_key).history!.vouching_grace_seconds;
    expect(grace(600)).toBe(600);
    expect(grace(10 * 86_400)).toBe(86_400);
    expect(grace('600')).toBe(86_400);
    expect(grace(undefined)).toBe(86_400);
  });
});

describe('the offline verifiers judge for the present with now', () => {
  const cases: Array<[string, string, (record: never, keys: NAKeyHistory, options?: { now?: string }) => boolean]> = [
    ['attestation', 'MembershipAttestation', verifyAttestationSignature as never],
    ['treaty', 'RecognitionTreaty', verifyTreatySignature as never],
    ['feed', 'SovereignRevocationFeed', verifyRevocationFeedSignature as never],
    ['grant', 'CapabilityGrant', verifyCapabilityGrant as never],
  ];
  for (const [slug, , verify] of cases) {
    it(`${slug}: vouches inside the grace, not past the horizon, and verifies at its own time`, () => {
      const inside = vector(`${slug}-old-key-within-grace`);
      const past = vector(`${slug}-old-key-after-horizon`);
      const h = historyOf(inside);
      expect(verify(inside.input.record as never, h, { now: inside.input.now })).toBe(true);
      expect(verify(past.input.record as never, h, { now: past.input.now })).toBe(false);
      expect(verify(past.input.record as never, h)).toBe(true);
      const fresh = vector(`${slug}-new-key`);
      expect(verify(fresh.input.record as never, h, { now: fresh.input.now })).toBe(true);
    });
  }

  it('a grant that starts more than 24 hours after its issue is refused, whatever key signed it', () => {
    for (const id of ['grant-valid-from-beyond-max-na-1', 'grant-valid-from-beyond-max-na-2']) {
      const v = vector(id);
      expect(verifyCapabilityGrant(v.input.record as unknown as CapabilityGrant, historyOf(v))).toBe(false);
    }
  });
});

describe('the grant holder', () => {
  const OLD = generateTestKeyPair();
  const NEW = generateTestKeyPair();
  const BEARER = generateTestKeyPair();
  const oldSigner = seedSigner(OLD.seedBase64, 'na-1');
  const newSigner = seedSigner(NEW.seedBase64, 'na-2');
  const history = twoKeys(OLD.pubBase64, NEW.pubBase64);
  const horizon = SUCCEEDED + 300_000 + 3_600_000;

  async function signed<T extends object>(record: T, signer: typeof oldSigner): Promise<T> {
    return { ...record, signature: await signCanonical(grantRecordCanonical(record), signer) };
  }

  async function grantOf(issuedAt: number, signer: typeof oldSigner) {
    const grant = await signed<CapabilityGrant>({
      grant_id: 'grant-1', bearer_key_id: 'device-key', bearer_public_key: BEARER.pubBase64, bearer_sovereign_id: 'site-7',
      capabilities: ['secret.rotate'], basis_kind: 'attestation', basis_id: 'attestation-1', basis_digest: 'e'.repeat(64),
      requester_sovereign_id: 'vendor', provider_sovereign_id: 'TEST', valid_from: iso(issuedAt),
      valid_until: iso(issuedAt + 20 * 3_600_000), max_uses: 3, max_uses_per_time_token: 2, parameter_envelope: {},
      basis_checks: [], policy_binding: { policies: [], policy_set_digest: 'f'.repeat(64), gate_outcomes: [], registry_gate_types: [] },
      issued_at: iso(issuedAt), issuer_sovereign_id: 'TEST', issued_by: signer.keyId,
    } as unknown as CapabilityGrant, signer);
    const timeToken = await signed<TimeToken>({
      time_token_id: 'token-0', grant_id: 'grant-1', use_sequence: 0, issued_at: iso(issuedAt), issuer_sovereign_id: 'TEST',
      issued_by: signer.keyId,
    }, signer);
    return { grant, timeToken };
  }

  function holder(grant: CapabilityGrant, timeToken: TimeToken, now: number): GrantHolder {
    const clients = new GenesisMeshClient({
      baseUrl: 'http://na', audience: 'TEST', signingKeyBase64: BEARER.seedBase64, keyId: 'ops',
      fetch: (async () => { throw new TypeError('offline'); }) as typeof fetch,
      recordOutbox: new MemoryOutbox<RecordOutboxEntry>(),
    });
    return new GrantHolder({
      clients, signer: seedSigner(BEARER.seedBase64, 'device-key'), naPublicKeys: history, grant, timeToken,
      now: () => new Date(now),
    });
  }

  async function feed(sequence: number, issuedAt: number, signer: typeof oldSigner): Promise<SovereignRevocationFeed> {
    const f: SovereignRevocationFeed = {
      feed_id: `feed-${signer.keyId}-${sequence}`, issuer_sovereign_id: 'TEST', sequence, issued_at: iso(issuedAt),
      revoked_attestation_ids: [], revocation_reasons: {}, issued_by: signer.keyId, signatures: [], revoked_grant_ids: [],
    };
    f.signatures = [await signCanonical(revocationFeedCanonical(f), signer)];
    return f;
  }

  it('refuses a grant of the old key once its horizon has passed', async () => {
    const { grant, timeToken } = await grantOf(SUCCEEDED - 3_600_000, oldSigner);
    expect(() => holder(grant, timeToken, horizon - 1000)).not.toThrow();
    expect(() => holder(grant, timeToken, horizon)).toThrow(GrantRefusedError);
  });

  it('a held grant of the old key ends as expired once its horizon passes (no fallback: nothing runs)', async () => {
    const { grant, timeToken } = await grantOf(SUCCEEDED - 3_600_000, oldSigner);
    let now = horizon - 60_000;
    const clients = new GenesisMeshClient({
      baseUrl: 'http://na', audience: 'TEST', signingKeyBase64: BEARER.seedBase64, keyId: 'ops',
      fetch: (async () => { throw new TypeError('offline'); }) as typeof fetch,
      recordOutbox: new MemoryOutbox<RecordOutboxEntry>(),
    });
    const held = new GrantHolder({
      clients, signer: seedSigner(BEARER.seedBase64, 'device-key'), naPublicKeys: history, grant, timeToken,
      now: () => new Date(now),
    });
    now = horizon;
    let ran = false;
    await expect(held.act({ capability: 'secret.rotate', request_parameters: {} }, async () => { ran = true; return {}; }))
      .rejects.toMatchObject({ name: 'GrantUnusableError', code: 'grant_expired' });
    expect(ran).toBe(false);
  });

  it("orders feeds by their signer's key, then by sequence", async () => {
    const { grant, timeToken } = await grantOf(SUCCEEDED + 600_000, newSigner);
    const h = holder(grant, timeToken, SUCCEEDED + 1_200_000);
    // A feed the old key signed inside its window, with a forged high sequence.
    expect(await h.updateRevocationFeed(await feed(1_000_000, SUCCEEDED - 1000, oldSigner))).toBe(true);
    // The new key's feed replaces it although its sequence is lower...
    expect(await h.updateRevocationFeed(await feed(12, SUCCEEDED + 900_000, newSigner))).toBe(true);
    expect(h.state.revocation_feed!.sequence).toBe(12);
    // ...and an old-key feed no longer replaces a new-key one, whatever its sequence.
    expect(await h.updateRevocationFeed(await feed(2_000_000, SUCCEEDED - 500, oldSigner))).toBe(false);
    // Within one key, a lower sequence never replaces a higher one.
    expect(await h.updateRevocationFeed(await feed(11, SUCCEEDED + 950_000, newSigner))).toBe(false);
    expect(await h.updateRevocationFeed(await feed(13, SUCCEEDED + 960_000, newSigner))).toBe(true);
  });

  it('a held feed of the old key stops blocking once its horizon has passed', async () => {
    const { grant, timeToken } = await grantOf(SUCCEEDED + 600_000, newSigner);
    let now = SUCCEEDED + 1_200_000;
    const clients = new GenesisMeshClient({
      baseUrl: 'http://na', audience: 'TEST', signingKeyBase64: BEARER.seedBase64, keyId: 'ops',
      fetch: (async () => { throw new TypeError('offline'); }) as typeof fetch,
      recordOutbox: new MemoryOutbox<RecordOutboxEntry>(),
    });
    // A list of keys has no ends or order: the old behaviour, by sequence alone.
    const flat = new GrantHolder({
      clients, signer: seedSigner(BEARER.seedBase64, 'device-key'), naPublicKeys: [OLD.pubBase64, NEW.pubBase64],
      grant, timeToken, now: () => new Date(now),
    });
    expect(await flat.updateRevocationFeed(await feed(1_000_000, SUCCEEDED - 1000, oldSigner))).toBe(true);
    expect(await flat.updateRevocationFeed(await feed(12, SUCCEEDED + 900_000, newSigner))).toBe(false);
    // With the history, past the horizon the old key's feed is refused outright.
    const h = holder(grant, timeToken, horizon);
    await expect(h.updateRevocationFeed(await feed(1_000_000, SUCCEEDED - 1000, oldSigner))).rejects.toThrow(GrantRefusedError);
    now = horizon;
    expect(await h.updateRevocationFeed(await feed(12, SUCCEEDED + 900_000, newSigner))).toBe(true);
  });
});
