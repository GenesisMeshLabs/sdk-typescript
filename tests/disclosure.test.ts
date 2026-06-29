import { DisclosureClient } from '../src/disclosure.js';
import { UnauthorizedError, ValidationError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type {
  AgreementRecord,
  CapabilityCommitment,
  CapabilityMembershipProof,
} from '../src/types.js';

const AGREEMENT: AgreementRecord = {
  agreement_id: 'agr-001',
  offerer_sovereign_id: 'ALPHA',
  responder_sovereign_id: 'BETA',
  agreed_terms: {
    capabilities: ['read:data', 'write:log'],
    scope: {},
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2026-12-31T00:00:00Z',
  },
  signed_at: '2026-01-03T00:00:00Z',
  graph_digest: 'sha256:ghi',
  issued_by: 'na-alpha',
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

const COMMITMENT: CapabilityCommitment = {
  commitment_id: 'cmt-001',
  agreement_id: 'agr-001',
  capabilities: ['read:data', 'write:log'],
  merkle_root: 'abc123',
  committed_at: '2026-06-01T00:00:00Z',
  issued_by: 'na-alpha',
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

const PROOF: CapabilityMembershipProof = {
  proof_id: 'prf-001',
  commitment_id: 'cmt-001',
  capability: 'read:data',
  merkle_path: ['hash1', 'hash2'],
  prover_sovereign_id: 'BETA',
  proved_at: '2026-06-01T00:00:00Z',
};

describe('DisclosureClient', () => {
  describe('commit', () => {
    it('posts to /admin/disclosure/commit and returns CapabilityCommitment', async () => {
      const fetch = mockFetch({ status: 201, body: COMMITMENT });
      const client = new DisclosureClient(buildTransport(fetch));
      const result = await client.commit({
        capabilities: ['read:data', 'write:log'],
        agreement: AGREEMENT,
      });
      expect(result.commitment_id).toBe('cmt-001');
      expect(result.capabilities).toEqual(['read:data', 'write:log']);
      expect(fetch.mock.calls[0][0]).toContain('/admin/disclosure/commit');
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new DisclosureClient(buildTransport(fetch));
      await expect(
        client.commit({ capabilities: ['read:data'], agreement: AGREEMENT }),
      ).rejects.toBeInstanceOf(UnauthorizedError);
    });
  });

  describe('nullifier', () => {
    it('posts to /admin/disclosure/nullifier and returns CapabilityNullifier', async () => {
      const nullifier = {
        nullifier_id: 'nul-001',
        proof_id: 'prf-001',
        commitment_id: 'cmt-001',
        issued_at: '2026-06-01T00:00:00Z',
        issued_by: 'na-alpha',
        signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
      };
      const fetch = mockFetch({ status: 201, body: nullifier });
      const client = new DisclosureClient(buildTransport(fetch));
      const result = await client.nullifier({ proof: PROOF });
      expect(result.nullifier_id).toBe('nul-001');
      expect(result.proof_id).toBe('prf-001');
      expect(fetch.mock.calls[0][0]).toContain('/admin/disclosure/nullifier');
    });
  });

  describe('prove', () => {
    it('posts to /disclosure/prove (unauthenticated) and returns proof', async () => {
      const fetch = mockFetch({ status: 200, body: PROOF });
      const client = new DisclosureClient(buildTransport(fetch));
      const result = await client.prove({
        capability: 'read:data',
        capabilities: ['read:data', 'write:log'],
        commitment: COMMITMENT,
        prover_sovereign_id: 'BETA',
      });
      expect(result.proof_id).toBe('prf-001');
      expect(result.capability).toBe('read:data');
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });

    it('throws ValidationError when capability is not in the committed set', async () => {
      const fetch = mockFetch({ status: 422, body: { error: 'Could not generate proof', code: 'prove_failed' } });
      const client = new DisclosureClient(buildTransport(fetch));
      await expect(
        client.prove({
          capability: 'delete:all',
          capabilities: ['read:data'],
          commitment: COMMITMENT,
          prover_sovereign_id: 'BETA',
        }),
      ).rejects.toBeInstanceOf(ValidationError);
    });
  });

  describe('verify', () => {
    it('posts to /disclosure/verify (unauthenticated)', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { valid: true, reason: 'ok', commitment_id: 'cmt-001' },
      });
      const client = new DisclosureClient(buildTransport(fetch));
      const result = await client.verify({ proof: PROOF, commitment: COMMITMENT });
      expect(result.valid).toBe(true);
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });
  });
});
