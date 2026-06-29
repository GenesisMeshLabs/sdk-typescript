import { AttestationClient } from '../src/attestation.js';
import { UnauthorizedError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { MembershipAttestation } from '../src/types.js';

const ATTESTATION: MembershipAttestation = {
  attestation_id: 'att-001',
  subject_id: 'node-xyz',
  roles: ['validator', 'observer'],
  issuer_sovereign_id: 'ALPHA',
  subject_public_key: null,
  claims: { department: 'engineering' },
  issued_at: '2026-06-01T00:00:00Z',
  expires_at: '2027-06-01T00:00:00Z',
  issued_by: 'na-alpha',
  status: 'active',
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

describe('AttestationClient', () => {
  describe('issue', () => {
    it('posts to /admin/attestations and returns MembershipAttestation', async () => {
      const fetch = mockFetch({ status: 201, body: ATTESTATION });
      const client = new AttestationClient(buildTransport(fetch));
      const result = await client.issue({
        subject_id: 'node-xyz',
        roles: ['validator', 'observer'],
      });
      expect(result.attestation_id).toBe('att-001');
      expect(result.roles).toEqual(['validator', 'observer']);
      expect(fetch.mock.calls[0][0]).toContain('/admin/attestations');
    });

    it('passes optional claims and validity_hours', async () => {
      const fetch = mockFetch({ status: 201, body: ATTESTATION });
      const client = new AttestationClient(buildTransport(fetch));
      await client.issue({
        subject_id: 'node-xyz',
        roles: ['validator'],
        validity_hours: 8760,
        claims: { department: 'engineering' },
      });
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.validity_hours).toBe(8760);
      expect(body.claims.department).toBe('engineering');
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new AttestationClient(buildTransport(fetch));
      await expect(
        client.issue({ subject_id: 'node-xyz', roles: ['validator'] }),
      ).rejects.toBeInstanceOf(UnauthorizedError);
    });
  });

  describe('revoke', () => {
    it('posts to /admin/attestations/:id/revoke', async () => {
      const fetch = mockFetch({ status: 200, body: { attestation_id: 'att-001', status: 'revoked' } });
      const client = new AttestationClient(buildTransport(fetch));
      const result = await client.revoke('att-001', { reason: 'key compromised' });
      expect(result.status).toBe('revoked');
      expect(fetch.mock.calls[0][0]).toContain('/admin/attestations/att-001/revoke');
    });

    it('accepts no reason (empty body)', async () => {
      const fetch = mockFetch({ status: 200, body: { attestation_id: 'att-001', status: 'revoked' } });
      const client = new AttestationClient(buildTransport(fetch));
      await client.revoke('att-001');
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body).toEqual({});
    });
  });

  describe('savePolicy', () => {
    it('posts to /admin/recognition-policy and returns RecognitionPolicyRecord', async () => {
      const fetch = mockFetch({
        status: 201,
        body: { policy_id: 'pol-001', local_sovereign_id: 'ALPHA', active: true },
      });
      const client = new AttestationClient(buildTransport(fetch));
      const result = await client.savePolicy({ recognition_policy: { allow_all: true } });
      expect(result.policy_id).toBe('pol-001');
      expect(result.active).toBe(true);
      expect(fetch.mock.calls[0][0]).toContain('/admin/recognition-policy');
    });
  });
});
