import { DataUsageClient } from '../src/data_usage.js';
import { NotFoundError, UnauthorizedError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { DataAccessIntent, DataLicensePolicy } from '../src/types.js';

const POLICY: DataLicensePolicy = {
  policy_id: 'pol-001',
  licensor_sovereign_id: 'ALPHA',
  licensee_sovereign_id: 'BETA',
  allowed_source_ids: ['src-a', 'src-b'],
  allowed_access_types: ['read', 'aggregate'],
  max_volume_bytes_per_session: 104857600,
  prohibited_classification_tags: ['pii', 'confidential'],
  valid_from: '2026-01-01T00:00:00Z',
  valid_until: '2026-12-31T00:00:00Z',
  signature: { key_id: 'na-alpha', sig: 'sig' },
};

const INTENT: DataAccessIntent = {
  intent_id: 'int-001',
  agent_sovereign_id: 'BETA',
  decision_id: 'dec-001',
  sources: [{ source_id: 'src-a', classification_tags: ['public'] }],
  access_types: ['read'],
  estimated_volume_bytes: 1024,
  declared_at: '2026-06-01T00:00:00Z',
  signatures: [{ key_id: 'na-beta', sig: 'sig' }],
};

describe('DataUsageClient', () => {
  describe('createPolicy', () => {
    it('posts to /admin/data-usage/policy and returns DataLicensePolicy', async () => {
      const fetch = mockFetch({ status: 201, body: POLICY });
      const client = new DataUsageClient(buildTransport(fetch));
      const result = await client.createPolicy({
        licensee_sovereign_id: 'BETA',
        allowed_source_ids: ['src-a', 'src-b'],
        allowed_access_types: ['read', 'aggregate'],
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2026-12-31T00:00:00Z',
      });
      expect(result.policy_id).toBe('pol-001');
      expect(result.allowed_access_types).toContain('read');
      expect(fetch.mock.calls[0][0]).toContain('/admin/data-usage/policy');
    });

    it('passes optional max_volume_bytes_per_session', async () => {
      const fetch = mockFetch({ status: 201, body: POLICY });
      const client = new DataUsageClient(buildTransport(fetch));
      await client.createPolicy({
        licensee_sovereign_id: 'BETA',
        allowed_source_ids: ['src-a'],
        allowed_access_types: ['read'],
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2026-12-31T00:00:00Z',
        max_volume_bytes_per_session: 104857600,
      });
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.max_volume_bytes_per_session).toBe(104857600);
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new DataUsageClient(buildTransport(fetch));
      await expect(
        client.createPolicy({
          licensee_sovereign_id: 'BETA',
          allowed_source_ids: ['src-a'],
          allowed_access_types: ['read'],
          valid_from: '2026-01-01T00:00:00Z',
          valid_until: '2026-12-31T00:00:00Z',
        }),
      ).rejects.toBeInstanceOf(UnauthorizedError);
    });
  });

  describe('createIntent', () => {
    it('posts to /admin/data-usage/intent and returns DataAccessIntent', async () => {
      const fetch = mockFetch({ status: 201, body: INTENT });
      const client = new DataUsageClient(buildTransport(fetch));
      const result = await client.createIntent({
        sources: [{ source_id: 'src-a', classification_tags: ['public'] }],
        access_types: ['read'],
      });
      expect(result.intent_id).toBe('int-001');
      expect(result.access_types).toContain('read');
      expect(fetch.mock.calls[0][0]).toContain('/admin/data-usage/intent');
    });

    it('passes optional decision_id', async () => {
      const fetch = mockFetch({ status: 201, body: INTENT });
      const client = new DataUsageClient(buildTransport(fetch));
      await client.createIntent({
        sources: [{ source_id: 'src-a', classification_tags: [] }],
        access_types: ['read'],
        decision_id: 'custom-dec-001',
      });
      const body = JSON.parse((fetch.mock.calls[0][1] as RequestInit).body as string);
      expect(body.decision_id).toBe('custom-dec-001');
    });
  });

  describe('getPolicy', () => {
    it('GETs /data-usage/policy (unauthenticated)', async () => {
      const fetch = mockFetch({ status: 200, body: POLICY });
      const client = new DataUsageClient(buildTransport(fetch));
      const result = await client.getPolicy();
      expect(result.policy_id).toBe('pol-001');
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect(init.method).toBe('GET');
    });

    it('throws NotFoundError when no policy is active', async () => {
      const fetch = mockFetch({ status: 404, body: { error: 'No active data usage policy', code: 'no_policy' } });
      const client = new DataUsageClient(buildTransport(fetch));
      await expect(client.getPolicy()).rejects.toBeInstanceOf(NotFoundError);
    });
  });

  describe('verify', () => {
    it('posts to /data-usage/verify (unauthenticated)', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { valid: true, violation_reason: null, violation_count: 0, violations: [] },
      });
      const client = new DataUsageClient(buildTransport(fetch));
      const result = await client.verify({ intent: INTENT, policy: POLICY });
      expect(result.valid).toBe(true);
      expect(result.violation_count).toBe(0);
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });

    it('returns violations for prohibited classification tags', async () => {
      const fetch = mockFetch({
        status: 200,
        body: {
          valid: false,
          violation_reason: 'prohibited_tag',
          violation_count: 1,
          violations: [{ violation_type: 'prohibited_tag', description: 'pii tag not allowed' }],
        },
      });
      const client = new DataUsageClient(buildTransport(fetch));
      const result = await client.verify({ intent: INTENT, policy: POLICY });
      expect(result.valid).toBe(false);
      expect(result.violations).toHaveLength(1);
    });
  });
});
