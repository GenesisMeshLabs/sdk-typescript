import { describe, expect, it } from '@jest/globals';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import {
  GenesisMeshClient,
  KeyHistoryError,
  MANIFEST_FILE,
  NAKeyHistory,
  agreementCanonical,
  anchorCanonical,
  anchorDigest,
  attestationCanonical,
  auditPackFiles,
  checkpointCanonical,
  decisionCanonical,
  naKeysAt,
  packReasons,
  parseExportLines,
  parseJson,
  policyCanonical,
  readAuditPackDir,
  receivedCanonical,
  signBytes,
  successionCanonical,
  treatyCanonical,
  verifyAgreement,
  verifyArchiveRecord,
  verifyAttestationSignature,
  verifyAuditPack,
  verifyBoundaryDecision,
  verifyEvidenceEvents,
  verifyKeyHistory,
  verifyPolicySignature,
  verifyRetentionCheckpoint,
  verifyStoreAnchors,
  verifyTreatySignature,
} from '../src/index.js';
import type {
  AgreementRecord, ArchiveRecord, AuditPackManifest, BoundaryDecision, BoundaryPolicy, ExecutorKeyInfo, GenesisBlock,
  KeySuccessionRecord, MembershipAttestation, RecognitionTreaty, RetentionCheckpoint, StoreAnchor,
} from '../src/index.js';
import { generateTestKeyPair, mockFetch } from './helpers.js';
import { vectors } from './vectors.js';

/**
 * NA key succession (1.5.0): records signed before and after a succession,
 * each verified with the key valid at its own time, the 300-second hand-over,
 * and the behaviour without a key history (any listed key, as before).
 */
const root = generateTestKeyPair();
const na1 = generateTestKeyPair();
const na2 = generateTestKeyPair();
const stranger = generateTestKeyPair();
const SOVEREIGN = 'sovereign-ts';
const SUCCESSION_AT = Date.UTC(2026, 0, 11);
const NEW_VALID_TO = '2028-01-11T00:00:00Z';

/** The UTC timestamp `seconds` after the succession takes effect. */
function at(seconds: number): string {
  return new Date(SUCCESSION_AT + seconds * 1000).toISOString().replace('.000Z', 'Z');
}

function sign(canonical: string, seedBase64: string): string {
  return signBytes(Buffer.from(canonical, 'utf-8'), seedBase64).toString('base64');
}

const genesis: GenesisBlock = {
  network_name: SOVEREIGN, network_version: 'v1', root_public_key: root.pubBase64,
  network_authority: { public_key: na1.pubBase64, valid_from: '2026-01-01T00:00:00Z', valid_to: '2026-04-01T00:00:00Z' },
  allowed_crypto_suites: ['ed25519', 'x25519'], allowed_transports: ['quic', 'wireguard'],
  policy_manifest: { hash: 'sha256:test', url: null }, bootstrap_anchors: [], signatures: [],
};
genesis.signatures.push({ key_id: 'root', sig: sign(receivedCanonical('GenesisBlock', genesis), root.seedBase64) });

const succession: KeySuccessionRecord = {
  succession_id: '00000000-0000-4000-8000-000000000401', sovereign_id: SOVEREIGN, key_sequence: 2,
  previous_key_id: 'na-1', previous_public_key: na1.pubBase64, new_key_id: 'na-2', new_public_key: na2.pubBase64,
  effective_at: at(0), new_valid_to: NEW_VALID_TO, issued_at: at(-6 * 86400), signatures: [],
};
succession.signatures.push(
  { key_id: 'root', sig: sign(successionCanonical(succession), root.seedBase64) },
  { key_id: 'na-1', sig: sign(successionCanonical(succession), na1.seedBase64) },
);

const verified = verifyKeyHistory(genesis, [succession], root.pubBase64);
const history = verified.history!;

describe('the key history', () => {
  it('accepts the genesis key and the succession from the root key held', () => {
    expect(verified.failures).toEqual([]);
    expect(history.keys.map(k => [k.key_sequence, k.key_id, k.valid_from, k.succeeded_at, k.valid_to_enforced])).toEqual([
      [1, 'na-1', null, at(0), false],
      [2, 'na-2', at(0), null, true],
    ]);
    expect(history.root_public_key).toBe(root.pubBase64);
  });

  it('gives the keys valid at a time, with the 300-second hand-over', () => {
    expect(history.keysAt(at(-1))).toEqual([na1.pubBase64]);
    expect(history.keysAt(at(0))).toEqual([na1.pubBase64, na2.pubBase64]);
    expect(history.keysAt(at(299))).toEqual([na1.pubBase64, na2.pubBase64]);
    expect(history.keysAt(at(300))).toEqual([na2.pubBase64]);
    expect(history.keysAt(NEW_VALID_TO)).toEqual([]);
    expect(history.signingKeyAt(at(10))?.key_sequence).toBe(2);
  });

  it('refuses a succession the outgoing key did not sign, and another root key', () => {
    const rootOnly = { ...succession, signatures: [succession.signatures[0]!] };
    expect(verifyKeyHistory(genesis, [rootOnly], root.pubBase64).failures)
      .toEqual([{ key_sequence: 2, reason: 'succession_invalid_previous_signature', detail: '' }]);
    expect(verifyKeyHistory(genesis, [succession], stranger.pubBase64).failures.map(f => f.reason))
      .toEqual(['genesis_root_mismatch']);
  });

  it('a list of keys is valid at every time', () => {
    expect(naKeysAt([na1.pubBase64], at(86400))).toEqual([na1.pubBase64]);
    expect(NAKeyHistory.ofKeys([na1.pubBase64]).keysAt(at(10 * 365 * 86400))).toEqual([na1.pubBase64]);
  });
});

describe('decisions are verified with the key valid when they were made', () => {
  const v = vectors();
  const decisionAt = (seconds: number, seed: string): BoundaryDecision => {
    const made = at(seconds);
    const decision = {
      ...v.allowed.decision, decision_made_at: made, decision_valid_until: at(seconds + 300),
    } as BoundaryDecision;
    return { ...decision, signature: { key_id: 'na', sig: sign(decisionCanonical(decision), seed) } };
  };
  const reason = (decision: BoundaryDecision, keys: NAKeyHistory | string[]) =>
    verifyBoundaryDecision(decision, { operatorPublicKeys: keys, atRecordTime: true }).reason;

  it('signed before the succession by the outgoing key', () => {
    expect(reason(decisionAt(-86400, na1.seedBase64), history)).toBe('authorized');
  });

  it('signed by the outgoing key inside the hand-over, and not after it', () => {
    expect(reason(decisionAt(299, na1.seedBase64), history)).toBe('authorized');
    expect(reason(decisionAt(300, na1.seedBase64), history)).toBe('na_key_not_valid_at_time');
  });

  it('signed by the new key from the succession on, never before it', () => {
    expect(reason(decisionAt(0, na2.seedBase64), history)).toBe('authorized');
    expect(reason(decisionAt(86400, na2.seedBase64), history)).toBe('authorized');
    expect(reason(decisionAt(-1, na2.seedBase64), history)).toBe('na_key_not_valid_at_time');
  });

  it('a key outside the history is an invalid signature', () => {
    expect(reason(decisionAt(86400, stranger.seedBase64), history)).toBe('invalid_signature');
  });

  it('without a key history, any listed key verifies, as before', () => {
    expect(reason(decisionAt(86400, na1.seedBase64), [na1.pubBase64, na2.pubBase64])).toBe('authorized');
    expect(reason(decisionAt(-1, na2.seedBase64), [na1.pubBase64, na2.pubBase64])).toBe('authorized');
  });

  it('judged now, an archived decision has expired', () => {
    const decision = decisionAt(-86400, na1.seedBase64);
    expect(verifyBoundaryDecision(decision, { operatorPublicKeys: history }).reason).toBe('decision_expired');
  });
});

describe('records outside the store, each at its own time', () => {
  const v = vectors();

  it('a retention checkpoint at its created_at', () => {
    const checkpointAt = (seconds: number, seed: string): RetentionCheckpoint => {
      const cp = { ...v.checkpoint, created_at: at(seconds) } as RetentionCheckpoint;
      return { ...cp, signature: { key_id: 'na', sig: sign(checkpointCanonical(cp), seed) } };
    };
    expect(verifyRetentionCheckpoint(checkpointAt(-60, na1.seedBase64), history)).toBe(true);
    expect(verifyRetentionCheckpoint(checkpointAt(120, na1.seedBase64), history)).toBe(true);
    expect(verifyRetentionCheckpoint(checkpointAt(301, na1.seedBase64), history)).toBe(false);
    expect(verifyRetentionCheckpoint(checkpointAt(301, na2.seedBase64), history)).toBe(true);
    expect(verifyRetentionCheckpoint(checkpointAt(301, na1.seedBase64), [na1.pubBase64])).toBe(true);
    // The export's start checkpoint too.
    const late = verifyEvidenceEvents([], { naPublicKeys: history, executorKeys: [], checkpoint: checkpointAt(301, na1.seedBase64) });
    expect(late.failures.map(f => f.reason)).toEqual(['invalid_signature']);
  });

  it('an attestation and a policy at their issued_at', () => {
    const attestationAt = (seconds: number, seed: string): MembershipAttestation => {
      const a = { ...v.attestation, issued_at: at(seconds), signatures: [] } as MembershipAttestation;
      return { ...a, signatures: [{ key_id: 'na', sig: sign(attestationCanonical(a), seed) }] };
    };
    expect(verifyAttestationSignature(attestationAt(-86400, na1.seedBase64), history)).toBe(true);
    expect(verifyAttestationSignature(attestationAt(86400, na1.seedBase64), history)).toBe(false);
    expect(verifyAttestationSignature(attestationAt(86400, na2.seedBase64), history)).toBe(true);
    expect(verifyAttestationSignature(attestationAt(86400, na1.seedBase64), [na1.pubBase64])).toBe(true);

    const policyAt = (seconds: number, seed: string): BoundaryPolicy => {
      const p = { ...v.policy, issued_at: at(seconds) } as BoundaryPolicy;
      return { ...p, signature: { key_id: 'na', sig: sign(policyCanonical(p), seed) } };
    };
    expect(verifyPolicySignature(policyAt(-1, na1.seedBase64), history)).toBe(true);
    expect(verifyPolicySignature(policyAt(-1, na2.seedBase64), history)).toBe(false);
    expect(verifyPolicySignature(policyAt(1, na2.seedBase64), history)).toBe(true);
  });

  it('a treaty at its issued_at, and an agreement at its established_at', () => {
    const treatyAt = (seconds: number, seed: string): RecognitionTreaty => {
      const t: RecognitionTreaty = {
        treaty_id: 'treaty-1', issuer_sovereign_id: SOVEREIGN, subject_sovereign_id: 'sovereign-b',
        subject_public_keys: [stranger.pubBase64], scope: { allowed_roles: ['role:client'] }, status: 'active',
        issued_at: at(seconds), valid_from: at(seconds), expires_at: NEW_VALID_TO, issued_by: 'na', metadata: {},
        signatures: [],
      };
      return { ...t, signatures: [{ key_id: 'na', sig: sign(treatyCanonical(t), seed) }] };
    };
    expect(verifyTreatySignature(treatyAt(-86400, na1.seedBase64), history)).toBe(true);
    expect(verifyTreatySignature(treatyAt(150, na1.seedBase64), history)).toBe(true);
    expect(verifyTreatySignature(treatyAt(86400, na1.seedBase64), history)).toBe(false);
    expect(verifyTreatySignature(treatyAt(86400, na2.seedBase64), history)).toBe(true);

    const agreementAt = (seconds: number, seed: string): AgreementRecord => {
      const record = {
        agreement_id: 'agreement-1', offer_id: 'offer-1', offerer_sovereign_id: SOVEREIGN, responder_sovereign_id: 'sovereign-b',
        agreed_terms: {
          capabilities: ['read'], scope: {}, valid_from: '2026-01-01T00:00:00Z', valid_until: NEW_VALID_TO,
          freshness_commitment: 0,
        },
        graph_digest: 'g', offerer_evidence: {}, responder_evidence: {},
        established_at: at(seconds), expires_at: NEW_VALID_TO, signatures: [],
      } as unknown as AgreementRecord;
      const sig = sign(agreementCanonical(record), seed);
      return { ...record, signatures: [{ key_id: 'na', sig }, { key_id: 'na', sig }] };
    };
    expect(verifyAgreement(agreementAt(-86400, na1.seedBase64), history, history).reason).toBe('accepted');
    expect(verifyAgreement(agreementAt(86400, na1.seedBase64), history, history).reason).toBe('invalid_offerer_signature');
    expect(verifyAgreement(agreementAt(86400, na2.seedBase64), history, history).reason).toBe('accepted');
    expect(verifyAgreement(agreementAt(86400, na1.seedBase64), [na1.pubBase64], [na1.pubBase64]).reason).toBe('accepted');
  });
});

describe('anchors across a succession', () => {
  const anchors: StoreAnchor[] = [];
  const anchorAt = (seconds: number, seed: string, storeSequence: number): StoreAnchor => {
    const previous = anchors[anchors.length - 1];
    const anchor: StoreAnchor = {
      anchor_sequence: anchors.length + 1, sovereign_id: SOVEREIGN, store_sequence: storeSequence,
      entry_digest: 'a'.repeat(64), anchored_at: at(seconds), issued_by: 'na',
      ...(previous ? { previous_anchor_digest: anchorDigest(previous) } : {}),
    };
    return { ...anchor, signature: { key_id: 'na', sig: sign(anchorCanonical(anchor), seed) } };
  };
  anchors.push(anchorAt(-3600, na1.seedBase64, 3));
  anchors.push(anchorAt(200, na1.seedBase64, 5));
  anchors.push(anchorAt(3600, na2.seedBase64, 8));

  it('each signed by the key valid at its anchored_at, the hand-over included', () => {
    expect(verifyStoreAnchors(anchors, { naPublicKeys: history, sovereignId: SOVEREIGN }).failures).toEqual([]);
  });

  it('an anchor after the hand-over signed by the outgoing key', () => {
    const late = anchors.slice(0, 2);
    const anchor = { ...anchors[2]!, signature: { key_id: 'na', sig: sign(anchorCanonical(anchors[2]!), na1.seedBase64) } };
    expect(verifyStoreAnchors([...late, anchor], { naPublicKeys: history }).failures.map(f => f.reason))
      .toEqual(['na_key_not_valid_at_time']);
    expect(verifyStoreAnchors([...late, anchor], { naPublicKeys: [na1.pubBase64] }).failures).toEqual([]);
    expect(verifyStoreAnchors(anchors, { naPublicKeys: [stranger.pubBase64] }).failures.map(f => f.reason))
      .toEqual(['anchor_invalid_signature', 'anchor_invalid_signature', 'anchor_invalid_signature']);
  });
});

describe('exports, archives and packs from the audit suite', () => {
  const suite = parseJson(readFileSync(fileURLToPath(new URL('./fixtures/conformance/audit.json', import.meta.url)), 'utf-8')) as
    { vectors: Array<{ id: string; input: Record<string, unknown> }> };
  const input = (id: string) => suite.vectors.find(v => v.id === id)!.input;
  const across = input('export-across-succession');
  const suiteHistory = verifyKeyHistory(across['genesis'], across['successions'] as unknown[], across['root_public_key'] as string).history!;
  const events = parseExportLines(across['lines'] as string);
  const keys = across['executor_keys'] as ExecutorKeyInfo[];

  it('without a key history, every listed key verifies every record (as before 1.5.0)', () => {
    const both = suiteHistory.allKeys();
    expect(verifyEvidenceEvents(events, { naPublicKeys: both, executorKeys: keys }).failures).toEqual([]);
    const outgoing = verifyEvidenceEvents(events, { naPublicKeys: [both[0]!], executorKeys: keys });
    expect(new Set(outgoing.failures.map(f => f.reason))).toEqual(new Set(['invalid_signature']));
  });

  it('counts the key succession and the archive', () => {
    const result = verifyEvidenceEvents(events, { naPublicKeys: suiteHistory, executorKeys: keys });
    expect([result.key_successions, result.archives]).toEqual([1, 1]);
  });

  it('verifies an archive record at its archived_at', () => {
    const archive = events.find(e => e.entry.entry_kind === 'archive')!.payload as unknown as ArchiveRecord;
    expect(verifyArchiveRecord(archive, suiteHistory)).toBe(true);
    expect(verifyArchiveRecord(archive, [suiteHistory.allKeys()[0]!])).toBe(false);
    expect(verifyArchiveRecord({ ...archive, location: 'elsewhere' }, suiteHistory)).toBe(false);
  });

  it('verifies a pack the NA returned, and one read from a directory', async () => {
    const frozen = input('pack-frozen-1.5.0');
    const files = frozen['files'] as Record<string, string>;
    const options = { rootPublicKey: frozen['root_public_key'] as string, heldAnchors: frozen['held_anchors'] as StoreAnchor[] };
    const { [MANIFEST_FILE]: manifest, ...rest } = files;
    const fromNa = auditPackFiles({ manifest: parseJson(manifest!) as AuditPackManifest, files: rest });
    expect(verifyAuditPack(fromNa, options).verified).toBe(true);

    const dir = mkdtempSync(join(tmpdir(), 'gm-pack-'));
    try {
      for (const [path, body] of Object.entries(fromNa)) {
        mkdirSync(dirname(join(dir, path)), { recursive: true });
        writeFileSync(join(dir, path), body);
      }
      const read = await readAuditPackDir(dir);
      expect(Object.keys(read).sort()).toEqual(Object.keys(files).sort());
      const result = verifyAuditPack(read, options);
      expect([result.verified, packReasons(result)]).toEqual([true, []]);
      expect(result.keys.map(k => k.key_sequence)).toEqual([1, 2]);
      writeFileSync(join(dir, 'notes.txt'), 'x');
      expect(packReasons(verifyAuditPack(await readAuditPackDir(dir), options))).toEqual(['manifest_unlisted_file']);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the key history client', () => {
  const view = {
    sovereign_id: SOVEREIGN, root_public_key: root.pubBase64, handover_seconds: 300, genesis, successions: [succession],
    keys: [], signing_key_sequence: 2,
  };
  const client = (body: unknown) => new GenesisMeshClient({
    baseUrl: 'http://localhost', fetch: mockFetch({ status: 200, body }) as unknown as typeof globalThis.fetch,
  });

  it('reads GET /na/key-history without operator headers', async () => {
    const fetch = mockFetch({ status: 200, body: view });
    const gm = new GenesisMeshClient({ baseUrl: 'http://localhost', fetch: fetch as unknown as typeof globalThis.fetch });
    expect(await gm.na.getKeyHistory()).toEqual(view);
    const [url, init] = fetch.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://localhost/na/key-history');
    expect(JSON.stringify(init.headers ?? {})).not.toContain('X-Admin');
  });

  it('verifies the history from the root key held, not the one served', async () => {
    const verifiedHistory = await client(view).na.verifiedKeyHistory(root.pubBase64);
    expect(verifiedHistory.allKeys()).toEqual([na1.pubBase64, na2.pubBase64]);
    const served = { ...view, root_public_key: stranger.pubBase64 };
    await expect(client(served).na.verifiedKeyHistory(stranger.pubBase64)).rejects.toMatchObject({
      name: 'KeyHistoryError', code: 'genesis_root_mismatch',
    });
    await expect(client(served).na.verifiedKeyHistory(stranger.pubBase64)).rejects.toBeInstanceOf(KeyHistoryError);
  });
});
