import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ConsensusClient } from '../src/consensus.js';
import { UnauthorizedError, ValidationError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { ConsensusProof, JustificationProof, ValidatorVote } from '../src/types.js';

const J_PROOF: JustificationProof = {
  proof_id: 'jp-001',
  decision_id: 'dec-001',
  trace: {
    trace_id: 'tr-001', decision_id: 'dec-001', agreement_id: 'agr-001', operator_sovereign_id: 'ALPHA',
    traced_at: '2026-06-01T00:00:00Z', entries: [], short_circuited_at: null, final_authorized: true,
  },
  proof_issued_at: '2026-06-01T00:00:00Z',
  issuer_sovereign_id: 'ALPHA',
  signature: { key_id: 'na-alpha', sig: 'sig' },
};

const VOTE: ValidatorVote = {
  vote_id: 'vt-001',
  proof_id: 'jp-001',
  decision_id: 'dec-001',
  validator_sovereign_id: 'ALPHA',
  vote: true,
  reason: 'evidence satisfactory',
  voted_at: '2026-06-01T00:00:00Z',
  context_digest: 'a'.repeat(64),
  signature: { key_id: 'ALPHA', sig: 'sig' },
};

const CONSENSUS: ConsensusProof = {
  consensus_id: 'con-001',
  proof_id: 'jp-001',
  decision_id: 'dec-001',
  votes: [VOTE],
  required_threshold: 1,
  validator_sovereign_ids: ['ALPHA'],
  reached_at: '2026-06-01T00:00:00Z',
  expires_at: '2026-06-01T01:00:00Z',
  cascade_assessment_digest: null,
  signature: { key_id: 'na-alpha', sig: 'sig' },
};

// Every field of the Python models, and only those: a missing key fails to
// compile, an extra or misspelt one fails to compile, and the runtime check
// below compares the list with a real Python-signed proof.
type Exhaustive<T, K extends readonly (keyof T)[]> = Exclude<keyof T, K[number]> extends never ? K : never;
const VOTE_KEYS = ['vote_id', 'proof_id', 'decision_id', 'validator_sovereign_id', 'vote', 'reason', 'voted_at',
  'context_digest', 'signature'] as const;
const PROOF_KEYS = ['consensus_id', 'proof_id', 'decision_id', 'required_threshold', 'validator_sovereign_ids',
  'votes', 'reached_at', 'expires_at', 'cascade_assessment_digest', 'signature'] as const;
const voteKeys: Exhaustive<ValidatorVote, typeof VOTE_KEYS> = VOTE_KEYS;
const proofKeys: Exhaustive<ConsensusProof, typeof PROOF_KEYS> = PROOF_KEYS;

describe('consensus wire contract', () => {
  const vectors = JSON.parse(readFileSync(fileURLToPath(new URL('./fixtures/conformance/consensus.json', import.meta.url)), 'utf-8')) as {
    vectors: { input: { proof: ConsensusProof } }[];
  };
  const proof = vectors.vectors[0]!.input.proof;

  it('ConsensusProof has exactly the fields of a Python-signed proof', () => {
    expect(Object.keys(proof).sort()).toEqual([...proofKeys].sort());
  });

  it('ValidatorVote has exactly the fields of a Python-signed vote', () => {
    expect(proof.votes.length).toBeGreaterThan(0);
    for (const vote of proof.votes) expect(Object.keys(vote).sort()).toEqual([...voteKeys].sort());
  });
});

describe('ConsensusClient', () => {
  describe('vote', () => {
    it('posts to /admin/consensus/vote and returns ValidatorVote', async () => {
      const fetch = mockFetch({ status: 201, body: VOTE });
      const client = new ConsensusClient(buildTransport(fetch));
      const result = await client.vote({ justification_proof: J_PROOF, vote: true });
      expect(result.vote_id).toBe('vt-001');
      expect(result.vote).toBe(true);
      expect(fetch.mock.calls[0][0]).toContain('/admin/consensus/vote');
    });

    it('sends vote: false for a negative vote', async () => {
      const negVote = { ...VOTE, vote: false };
      const fetch = mockFetch({ status: 201, body: negVote });
      const client = new ConsensusClient(buildTransport(fetch));
      await client.vote({ justification_proof: J_PROOF, vote: false, reason: 'insufficient evidence' });
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.vote).toBe(false);
      expect(body.reason).toBe('insufficient evidence');
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new ConsensusClient(buildTransport(fetch));
      await expect(
        client.vote({ justification_proof: J_PROOF, vote: true }),
      ).rejects.toBeInstanceOf(UnauthorizedError);
    });
  });

  describe('proof', () => {
    it('posts to /admin/consensus/proof and returns ConsensusProof', async () => {
      const fetch = mockFetch({ status: 201, body: CONSENSUS });
      const client = new ConsensusClient(buildTransport(fetch));
      const result = await client.proof({
        justification_proof: J_PROOF,
        votes: [VOTE],
        required_threshold: 1,
        validator_sovereign_ids: ['ALPHA'],
      });
      expect(result.consensus_id).toBe('con-001');
      expect(result.votes).toHaveLength(1);
      expect(fetch.mock.calls[0][0]).toContain('/admin/consensus/proof');
    });

    it('throws ValidationError when threshold is not met', async () => {
      const fetch = mockFetch({
        status: 422,
        body: { error: 'Not enough valid votes', code: 'proof_assembly_failed' },
      });
      const client = new ConsensusClient(buildTransport(fetch));
      await expect(
        client.proof({
          justification_proof: J_PROOF,
          votes: [VOTE],
          required_threshold: 5,
          validator_sovereign_ids: ['ALPHA', 'BETA', 'GAMMA', 'DELTA', 'EPSILON'],
        }),
      ).rejects.toBeInstanceOf(ValidationError);
    });
  });

  describe('verify', () => {
    it('posts to /consensus/verify (unauthenticated)', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { valid: true, reason: 'ok', consensus_id: 'con-001' },
      });
      const client = new ConsensusClient(buildTransport(fetch));
      const result = await client.verify({ proof: CONSENSUS });
      expect(result.valid).toBe(true);
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });

    it('returns valid=false for bad signatures', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { valid: false, reason: 'bad_signature', consensus_id: null },
      });
      const client = new ConsensusClient(buildTransport(fetch));
      const result = await client.verify({ proof: CONSENSUS });
      expect(result.valid).toBe(false);
    });
  });
});
