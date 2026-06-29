import { ConsensusClient } from '../src/consensus.js';
import { UnauthorizedError, ValidationError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { ConsensusProof, JustificationProof, ValidatorVote } from '../src/types.js';

const J_PROOF: JustificationProof = {
  proof_id: 'jp-001',
  decision_id: 'dec-001',
};

const VOTE: ValidatorVote = {
  vote_id: 'vt-001',
  proof_id: 'jp-001',
  decision_id: 'dec-001',
  validator_sovereign_id: 'ALPHA',
  vote: true,
  reason: 'evidence satisfactory',
  voted_at: '2026-06-01T00:00:00Z',
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

const CONSENSUS: ConsensusProof = {
  consensus_id: 'con-001',
  proof_id: 'jp-001',
  decision_id: 'dec-001',
  votes: [VOTE],
  required_threshold: 1,
  validator_sovereign_ids: ['ALPHA'],
  assembled_at: '2026-06-01T00:00:00Z',
  issued_by: 'na-alpha',
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

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
