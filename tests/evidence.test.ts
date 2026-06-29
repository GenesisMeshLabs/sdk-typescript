import { EvidenceClient } from '../src/evidence.js';
import { UnauthorizedError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { TrustEvidence } from '../src/types.js';

const EVIDENCE: TrustEvidence = {
  evidence_id: 'ev-001',
  source_sovereign_id: 'ALPHA',
  target_sovereign_id: 'BETA',
  verdict: 'trusted',
  reason: 'long-standing member',
  graph_digest: 'sha256:abc',
  issued_at: '2026-06-01T00:00:00Z',
  issued_by: 'na-alpha',
  signals: [],
  signatures: [{ key_id: 'na-alpha', sig: 'sig' }],
};

describe('EvidenceClient', () => {
  describe('build', () => {
    it('posts to /admin/trust-evidence and returns TrustEvidence', async () => {
      const fetch = mockFetch({ status: 201, body: EVIDENCE });
      const client = new EvidenceClient(buildTransport(fetch));
      const result = await client.build({
        decision: {
          source_sovereign_id: 'ALPHA',
          target_sovereign_id: 'BETA',
          verdict: 'trusted',
          reason: 'long-standing member',
        },
      });
      expect(result.evidence_id).toBe('ev-001');
      expect(result.verdict).toBe('trusted');
      expect(fetch.mock.calls[0][0]).toContain('/admin/trust-evidence');
    });

    it('passes optional graph_digest', async () => {
      const fetch = mockFetch({ status: 201, body: EVIDENCE });
      const client = new EvidenceClient(buildTransport(fetch));
      await client.build({
        decision: { source_sovereign_id: 'ALPHA', target_sovereign_id: 'BETA', verdict: 'trusted' },
        graph_digest: 'sha256:custom',
      });
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.graph_digest).toBe('sha256:custom');
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new EvidenceClient(buildTransport(fetch));
      await expect(
        client.build({ decision: { source_sovereign_id: 'A', target_sovereign_id: 'B', verdict: 'trusted' } }),
      ).rejects.toBeInstanceOf(UnauthorizedError);
    });
  });

  describe('verify', () => {
    it('posts to /trust-evidence/verify (unauthenticated)', async () => {
      const fetch = mockFetch({
        status: 200,
        body: {
          accepted: true,
          reason: 'ok',
          evidence_id: 'ev-001',
          issuer_sovereign_id: 'ALPHA',
          verdict: 'trusted',
        },
      });
      const client = new EvidenceClient(buildTransport(fetch));
      const result = await client.verify({ evidence: EVIDENCE });
      expect(result.accepted).toBe(true);
      expect(result.verdict).toBe('trusted');
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });

    it('passes optional expected_graph_digest', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { accepted: false, reason: 'graph_mismatch', evidence_id: null, issuer_sovereign_id: null, verdict: null },
      });
      const client = new EvidenceClient(buildTransport(fetch));
      const result = await client.verify({
        evidence: EVIDENCE,
        expected_graph_digest: 'sha256:different',
      });
      expect(result.accepted).toBe(false);
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.expected_graph_digest).toBe('sha256:different');
    });
  });
});
