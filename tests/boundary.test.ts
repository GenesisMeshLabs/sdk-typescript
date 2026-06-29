import { BoundaryClient } from '../src/boundary.js';
import { UnauthorizedError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { AgreementRecord, BoundaryDecision } from '../src/types.js';

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

const DECISION: BoundaryDecision = {
  decision_id: 'dec-001',
  agreement_id: 'agr-001',
  requested_capability: 'read:data',
  authorized: true,
  reason: 'capability in agreement',
  context: {},
  decided_at: '2026-06-01T00:00:00Z',
  issued_by: 'na-alpha',
  operator_id: 'operator-local',
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

describe('BoundaryClient', () => {
  describe('decide', () => {
    it('posts to /admin/boundary/decide and returns BoundaryDecision', async () => {
      const fetch = mockFetch({ status: 201, body: DECISION });
      const client = new BoundaryClient(buildTransport(fetch));
      const result = await client.decide({
        agreement: AGREEMENT,
        requested_capability: 'read:data',
      });
      expect(result.decision_id).toBe('dec-001');
      expect(result.authorized).toBe(true);
      expect(fetch.mock.calls[0][0]).toContain('/admin/boundary/decide');
    });

    it('passes optional context field', async () => {
      const fetch = mockFetch({ status: 201, body: DECISION });
      const client = new BoundaryClient(buildTransport(fetch));
      await client.decide({
        agreement: AGREEMENT,
        requested_capability: 'read:data',
        context: { session_id: 'sess-123' },
      });
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.context.session_id).toBe('sess-123');
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new BoundaryClient(buildTransport(fetch));
      await expect(
        client.decide({ agreement: AGREEMENT, requested_capability: 'read:data' }),
      ).rejects.toBeInstanceOf(UnauthorizedError);
    });

    it('returns unauthorized decision for unknown capability', async () => {
      const unauthorized = { ...DECISION, authorized: false, reason: 'not_in_agreement' };
      const fetch = mockFetch({ status: 201, body: unauthorized });
      const client = new BoundaryClient(buildTransport(fetch));
      const result = await client.decide({
        agreement: AGREEMENT,
        requested_capability: 'delete:everything',
      });
      expect(result.authorized).toBe(false);
    });
  });

  describe('verify', () => {
    it('posts to /boundary/verify (unauthenticated)', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { accepted: true, authorized: true, reason: 'ok', decision_id: 'dec-001' },
      });
      const client = new BoundaryClient(buildTransport(fetch));
      const result = await client.verify({ decision: DECISION });
      expect(result.accepted).toBe(true);
      expect(result.authorized).toBe(true);
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });

    it('returns accepted=false for bad signature', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { accepted: false, authorized: false, reason: 'bad_signature', decision_id: null },
      });
      const client = new BoundaryClient(buildTransport(fetch));
      const result = await client.verify({ decision: DECISION });
      expect(result.accepted).toBe(false);
    });
  });
});
