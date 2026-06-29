import { AgreementClient } from '../src/agreement.js';
import { UnauthorizedError, ValidationError } from '../src/errors.js';
import { buildTransport, mockFetch } from './helpers.js';
import type { AgreementRecord, CapabilityCounter, CapabilityOffer } from '../src/types.js';

const OFFER: CapabilityOffer = {
  offer_id: 'offer-001',
  offerer_sovereign_id: 'ALPHA',
  responder_sovereign_id: 'BETA',
  requested_terms: {
    capabilities: ['read:data'],
    scope: {},
    valid_from: '2026-01-01T00:00:00Z',
    valid_until: '2026-12-31T00:00:00Z',
  },
  expires_at: '2026-01-15T00:00:00Z',
  graph_digest: 'sha256:abc',
  issued_by: 'na-alpha',
  issued_at: '2026-01-01T00:00:00Z',
  signatures: [{ key_id: 'na-alpha', sig: 'base64sig' }],
};

const COUNTER: CapabilityCounter = {
  counter_id: 'counter-001',
  original_offer_id: 'offer-001',
  offerer_sovereign_id: 'ALPHA',
  responder_sovereign_id: 'BETA',
  counter_terms: OFFER.requested_terms,
  graph_digest: 'sha256:def',
  issued_by: 'na-beta',
  issued_at: '2026-01-02T00:00:00Z',
  signatures: [{ key_id: 'na-beta', sig: 'base64sig2' }],
};

const AGREEMENT: AgreementRecord = {
  agreement_id: 'agr-001',
  offerer_sovereign_id: 'ALPHA',
  responder_sovereign_id: 'BETA',
  agreed_terms: OFFER.requested_terms,
  signed_at: '2026-01-03T00:00:00Z',
  graph_digest: 'sha256:ghi',
  issued_by: 'na-alpha',
  signatures: [{ key_id: 'na-alpha', sig: 'base64sig3' }],
};

describe('AgreementClient', () => {
  describe('offer', () => {
    it('posts to /admin/agreements/offer and returns CapabilityOffer', async () => {
      const fetch = mockFetch({ status: 201, body: OFFER });
      const client = new AgreementClient(buildTransport(fetch));
      const result = await client.offer({
        responder_sovereign_id: 'BETA',
        capabilities: ['read:data'],
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2026-12-31T00:00:00Z',
        expires_at: '2026-01-15T00:00:00Z',
      });
      expect(result.offer_id).toBe('offer-001');
      expect(fetch.mock.calls[0][0]).toContain('/admin/agreements/offer');
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const client = new AgreementClient(buildTransport(fetch));
      await expect(client.offer({
        responder_sovereign_id: 'BETA',
        capabilities: ['read:data'],
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2026-12-31T00:00:00Z',
        expires_at: '2026-01-15T00:00:00Z',
      })).rejects.toBeInstanceOf(UnauthorizedError);
    });
  });

  describe('counter', () => {
    it('posts to /admin/agreements/counter and returns CapabilityCounter', async () => {
      const fetch = mockFetch({ status: 201, body: COUNTER });
      const client = new AgreementClient(buildTransport(fetch));
      const result = await client.counter({
        offer: OFFER,
        capabilities: ['read:data'],
        valid_from: '2026-01-01T00:00:00Z',
        valid_until: '2026-12-31T00:00:00Z',
      });
      expect(result.counter_id).toBe('counter-001');
      expect(result.original_offer_id).toBe('offer-001');
      expect(fetch.mock.calls[0][0]).toContain('/admin/agreements/counter');
    });
  });

  describe('accept', () => {
    it('accepts an offer and returns AgreementRecord', async () => {
      const fetch = mockFetch({ status: 201, body: AGREEMENT });
      const client = new AgreementClient(buildTransport(fetch));
      const result = await client.accept({ offer: OFFER });
      expect(result.agreement_id).toBe('agr-001');
      expect(fetch.mock.calls[0][0]).toContain('/admin/agreements/accept');
    });

    it('accepts a counter and returns AgreementRecord', async () => {
      const fetch = mockFetch({ status: 201, body: AGREEMENT });
      const client = new AgreementClient(buildTransport(fetch));
      const result = await client.accept({ counter: COUNTER, original_offer: OFFER });
      expect(result.agreement_id).toBe('agr-001');
    });

    it('throws ValidationError on 422', async () => {
      const fetch = mockFetch({ status: 422, body: { error: 'Invalid', code: 'invalid_offer' } });
      const client = new AgreementClient(buildTransport(fetch));
      await expect(client.accept({ offer: OFFER })).rejects.toBeInstanceOf(ValidationError);
    });
  });

  describe('verify', () => {
    it('posts to /agreements/verify (no auth headers)', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { accepted: true, reason: 'ok', agreement_id: 'agr-001' },
      });
      const client = new AgreementClient(buildTransport(fetch));
      const result = await client.verify({ agreement: AGREEMENT });
      expect(result.accepted).toBe(true);
      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect((init.headers as Record<string, string>)['X-Admin-Key-Id']).toBeUndefined();
    });

    it('returns false for an unrecognized agreement', async () => {
      const fetch = mockFetch({
        status: 200,
        body: { accepted: false, reason: 'unknown_agreement', agreement_id: null },
      });
      const client = new AgreementClient(buildTransport(fetch));
      const result = await client.verify({ agreement: AGREEMENT });
      expect(result.accepted).toBe(false);
      expect(result.agreement_id).toBeNull();
    });
  });
});
