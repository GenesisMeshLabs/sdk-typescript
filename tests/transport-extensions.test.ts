import { describe, expect, it, jest } from '@jest/globals';
import { GenesisMeshClient, HttpTransport, SecretMaterialError, parseJson, canonicalJson, seedSigner, signBytes } from '../src/index.js';
import { buildTransport, mockFetch, TEST_KEY } from './helpers.js';
import { vectors } from './vectors.js';

describe('transport extensions', () => {
  it.each([429, 502, 503, 504])('retries GET after %s with a fresh admin nonce', async status => {
    const fetch = mockFetch({ status, body: {} }, { status: 200, body: { ok: true } });
    const http = buildTransport(fetch, { retry: { attempts: 1, baseDelayMs: 0 } });
    expect(await http.adminGet('/admin/test')).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(2);
    const headers = fetch.mock.calls.map(call => (call[1] as RequestInit).headers as Record<string, string>);
    expect(headers[0]['X-Admin-Nonce']).not.toBe(headers[1]['X-Admin-Nonce']);
  });
  it('retries network failures but stops at the configured bound', async () => {
    const fetch = jest.fn<typeof globalThis.fetch>().mockRejectedValue(new Error('offline'));
    await expect(buildTransport(fetch, { retry: { attempts: 2, baseDelayMs: 0 } }).publicGet('/test')).rejects.toThrow('offline');
    expect(fetch).toHaveBeenCalledTimes(3);
  });
  it('does not retry by default or for state-creating POSTs', async () => {
    for (const options of [{}, { retry: { attempts: 2, baseDelayMs: 0 } }]) {
      const fetch = mockFetch({ status: 503, body: {} });
      await expect(buildTransport(fetch, options).adminPost('/admin/attestations', {})).rejects.toThrow();
      expect(fetch).toHaveBeenCalledTimes(1);
    }
    const fetch = mockFetch({ status: 503, body: {} });
    await expect(buildTransport(fetch).publicGet('/test')).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it.each([400, 401, 403, 409, 422])('does not retry HTTP %s', async status => {
    const fetch = mockFetch({ status, body: {} });
    await expect(buildTransport(fetch, { retry: { attempts: 2, baseDelayMs: 0 } }).publicGet('/test')).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });
  it('retries explicitly idempotent verification and evidence POSTs', async () => {
    const fetch = mockFetch({ status: 503, body: {} }, { status: 200, body: { status: 'duplicate' } });
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://local', retry: { attempts: 1, baseDelayMs: 0 }, fetch: fetch as unknown as typeof globalThis.fetch });
    expect(await gm.evidenceStore.submit(vectors().executions[0])).toEqual({ status: 'duplicate' });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('uses async signers in preference to seeds, without caching or fallback', async () => {
    const fetch = mockFetch({ status: 200, body: {} });
    const sign = jest.fn(async (bytes: Buffer) => signBytes(bytes, TEST_KEY.seedBase64));
    const http = buildTransport(fetch, { signingKeyBase64: 'invalid', signer: { keyId: 'HSM', sign } });
    await http.adminGet('/a'); await http.adminGet('/b');
    expect(http.keyId).toBe('HSM'); expect(sign).toHaveBeenCalledTimes(2);
    sign.mockRejectedValue(new Error('signing unavailable'));
    await expect(http.adminGet('/c')).rejects.toThrow('signing unavailable');
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('preserves integral Python floats in response parsing and outgoing bodies', async () => {
    const fetch = mockFetch({ status: 200, body: '{"condition":{"max":90.0}}' });
    const http = buildTransport(fetch);
    const parsed = await http.publicGet('/test');
    expect(canonicalJson(parsed)).toBe('{"condition":{"max":90.0}}');
    await http.adminPost('/test', parsed);
    expect((fetch.mock.calls[1][1] as RequestInit).body).toBe('{"condition":{"max":90.0}}');
  });
  it('handles raw NDJSON and malformed responses', async () => {
    const fetch = mockFetch({ status: 200, body: 'line\n' }, { status: 200, body: 'bad' }, { status: 503, body: 'bad' });
    const http = buildTransport(fetch);
    expect(await http.adminGetText('/export')).toBe('line\n');
    await expect(http.publicGet('/bad')).rejects.toMatchObject({ name: 'NetworkError' });
    await expect(http.adminGetText('/bad')).rejects.toMatchObject({ status: 503 });
  });
  it.each([Infinity, -1, 1.5, 11])('rejects invalid retry attempts %s', attempts => {
    expect(() => new HttpTransport({ audience: 'TEST', baseUrl: 'http://local', retry: { attempts } })).toThrow('retry');
  });
  it('rejects invalid retry delay', () => {
    expect(() => new HttpTransport({ audience: 'TEST', baseUrl: 'http://local', retry: { attempts: 1, baseDelayMs: Infinity } })).toThrow('retry');
  });
  it('keeps seed signers usable directly', async () => {
    expect((await seedSigner(TEST_KEY.seedBase64, 'key').sign(Buffer.from('message'))).length).toBe(64);
    expect(parseJson('{"x":1}')).toEqual({ x: 1 });
  });
});

describe('preflight guards', () => {
  it('blocks context secrets before signing or sending evaluation', async () => {
    const fetch = mockFetch({ status: 200, body: {} });
    const sign = jest.fn(async () => Buffer.alloc(64));
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://local', signer: { keyId: 'key', sign }, fetch: fetch as unknown as typeof globalThis.fetch });
    await expect(gm.boundary.evaluate({ attestation_id: 'a', requested_capability: 'rotate', context: { attributes: { nested: { client_secret: 'no' } } } })).rejects.toBeInstanceOf(SecretMaterialError);
    expect(fetch).not.toHaveBeenCalled(); expect(sign).not.toHaveBeenCalled();
  });
  it('blocks direct evidence submission containing secret material', async () => {
    const fetch = mockFetch({ status: 200, body: {} });
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://local', fetch: fetch as unknown as typeof globalThis.fetch });
    await expect(gm.evidenceStore.submit({ ...vectors().executions[0], execution_parameters: { secret: 'no' } })).rejects.toBeInstanceOf(SecretMaterialError);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('response-body network failures', () => {
  it('retries a dropped response body for idempotent requests', async () => {
    const fetch = jest.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce({ ok: true, status: 200, text: async () => { throw new Error('connection reset'); } } as unknown as Response)
      .mockResolvedValueOnce(new Response('{"ok":true}'));
    expect(await buildTransport(fetch, { retry: { attempts: 1, baseDelayMs: 0 } }).publicGet('/test')).toEqual({ ok: true });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it('does not retry a state-creating request after a dropped response body', async () => {
    const fetch = jest.fn<typeof globalThis.fetch>().mockResolvedValue({ ok: true, status: 201, text: async () => { throw new Error('connection reset'); } } as unknown as Response);
    await expect(buildTransport(fetch, { retry: { attempts: 1, baseDelayMs: 0 } }).adminPost('/admin/attestations', {})).rejects.toMatchObject({ name: 'NetworkError' });
    expect(fetch).toHaveBeenCalledTimes(1);
  });
});

describe('boundary evaluation basis', () => {
  it('sends an agreement basis without an attestation ID', async () => {
    const fetch = mockFetch({ status: 200, body: vectors().allowed });
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://local', signingKeyBase64: TEST_KEY.seedBase64, fetch: fetch as unknown as typeof globalThis.fetch });
    const agreement = { agreement_id: 'agreement', offerer_sovereign_id: 'a', responder_sovereign_id: 'b',
      agreed_terms: { capabilities: ['read'], scope: {}, valid_from: '2026-01-01T00:00:00Z', valid_until: '2027-01-01T00:00:00Z', freshness_commitment: 0 },
      offer_id: 'offer', offerer_evidence: {}, responder_evidence: {}, graph_digest: 'digest',
      established_at: '2026-01-01T00:00:00Z', expires_at: '2027-01-01T00:00:00Z', signatures: [] };
    expect(await gm.boundary.evaluate({ agreement, requested_capability: 'read' })).toHaveProperty('decision');
    const body = JSON.parse(String((fetch.mock.calls[0][1] as RequestInit).body));
    expect(body.agreement).toEqual(agreement); expect(body.attestation_id).toBeUndefined();
  });
  it('rejects missing or ambiguous bases before HTTP', async () => {
    const fetch = mockFetch({ status: 200, body: {} });
    const gm = new GenesisMeshClient({ audience: 'TEST', baseUrl: 'http://local', fetch: fetch as unknown as typeof globalThis.fetch });
    for (const params of [{ requested_capability: 'read' }, { requested_capability: 'read', attestation_id: 'a', agreement: {} }]) {
      await expect(gm.boundary.evaluate(params as unknown as import('../src/boundary.js').EvaluateParams)).rejects.toThrow('exactly one');
    }
    expect(fetch).not.toHaveBeenCalled();
  });
});
