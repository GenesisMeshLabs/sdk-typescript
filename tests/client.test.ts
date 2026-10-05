import { jest } from '@jest/globals';
import { HttpTransport } from '../src/client.js';
import {
  BadRequestError,
  NetworkError,
  RateLimitError,
  UnauthorizedError,
} from '../src/errors.js';
import { buildTransport, mockFetch, TEST_KEY } from './helpers.js';

describe('HttpTransport', () => {
  describe('constructor', () => {
    it('strips trailing slash from baseUrl', () => {
      const t = new HttpTransport({ audience: 'TEST', baseUrl: 'http://localhost:9443/' });
      expect((t as unknown as { baseUrl: string }).baseUrl).toBe('http://localhost:9443');
    });

    it('defaults keyId to operator-local', () => {
      const t = new HttpTransport({ audience: 'TEST', baseUrl: 'http://localhost:9443' });
      expect((t as unknown as { keyId: string }).keyId).toBe('operator-local');
    });
  });

  describe('adminPost', () => {
    it('sends X-Admin-* headers', async () => {
      const fetch = mockFetch({ status: 201, body: { ok: true } });
      const transport = buildTransport(fetch);
      await transport.adminPost('/admin/test', { foo: 'bar' });

      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      const headers = init.headers as Record<string, string>;
      expect(headers['X-Admin-Key-Id']).toBe('operator-local');
      expect(typeof headers['X-Admin-Signature']).toBe('string');
      expect(typeof headers['X-Admin-Timestamp']).toBe('string');
      expect(typeof headers['X-Admin-Nonce']).toBe('string');
    });

    it('throws when signingKeyBase64 is missing', async () => {
      const transport = new HttpTransport({ audience: 'TEST', baseUrl: 'http://localhost:9443' });
      await expect(transport.adminPost('/admin/test', {})).rejects.toThrow(
        'signingKeyBase64 is required',
      );
    });

    it('throws UnauthorizedError on 401', async () => {
      const fetch = mockFetch({ status: 401, body: { error: 'Unauthorized', code: 'admin_auth_failed' } });
      const transport = buildTransport(fetch);
      await expect(transport.adminPost('/admin/test', {})).rejects.toBeInstanceOf(UnauthorizedError);
    });

    it('throws RateLimitError on 429', async () => {
      const fetch = mockFetch({ status: 429, body: { error: 'Rate limit exceeded', code: 'rate_limit_exceeded' } });
      const transport = buildTransport(fetch);
      await expect(transport.adminPost('/admin/test', {})).rejects.toBeInstanceOf(RateLimitError);
    });

    it('throws BadRequestError on 400', async () => {
      const fetch = mockFetch({ status: 400, body: { error: 'Bad request', code: 'missing_fields' } });
      const transport = buildTransport(fetch);
      await expect(transport.adminPost('/admin/test', {})).rejects.toBeInstanceOf(BadRequestError);
    });
  });

  describe('publicPost', () => {
    it('sends no auth headers', async () => {
      const fetch = mockFetch({ status: 200, body: { ok: true } });
      const transport = buildTransport(fetch);
      await transport.publicPost('/verify', { data: 1 });

      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      const headers = init.headers as Record<string, string>;
      expect(headers['X-Admin-Key-Id']).toBeUndefined();
    });
  });

  describe('publicGet', () => {
    it('uses GET method', async () => {
      const fetch = mockFetch({ status: 200, body: { value: 42 } });
      const transport = buildTransport(fetch);
      await transport.publicGet('/data-usage/policy');

      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      expect(init.method).toBe('GET');
    });
  });

  describe('network errors', () => {
    it('wraps fetch exceptions as NetworkError', async () => {
      const fetch = jest.fn<() => Promise<Response>>().mockRejectedValue(new Error('ECONNREFUSED'));
      const transport = buildTransport(fetch as unknown as jest.Mock);
      await expect(transport.publicPost('/test', {})).rejects.toBeInstanceOf(NetworkError);
    });
  });

  describe('admin auth signing', () => {
    it('produces a consistent key id in headers', async () => {
      const fetch = mockFetch({ status: 201, body: {} });
      const transport = buildTransport(fetch, { keyId: 'my-key' });
      await transport.adminPost('/admin/test', {});

      const [, init] = fetch.mock.calls[0] as [string, RequestInit];
      const headers = init.headers as Record<string, string>;
      expect(headers['X-Admin-Key-Id']).toBe('my-key');
    });

    it('uses a valid base64-decodable seed', () => {
      expect(() => Buffer.from(TEST_KEY.seedBase64, 'base64')).not.toThrow();
      expect(Buffer.from(TEST_KEY.seedBase64, 'base64').length).toBe(32);
    });
  });
});

describe('admin signature audience (signature version 2)', () => {
  it('reads the NA public key once from /sovereign.json and signs the request it sends', async () => {
    const fetch = mockFetch(
      { status: 200, body: { network_authority: { public_key: 'NA-PUBLIC-KEY' } } },
      { status: 201, body: { token_id: 't1' } },
      { status: 201, body: { token_id: 't2' } },
    );
    const t = buildTransport(fetch, { audience: undefined });
    await t.adminPost('/admin/invite', { roles: ['role:client'] });
    await t.adminPost('/admin/invite', { roles: ['role:client'] });
    const urls = fetch.mock.calls.map(c => String(c[0]));
    expect(urls).toEqual([
      'http://127.0.0.1:9443/sovereign.json',
      'http://127.0.0.1:9443/admin/invite',
      'http://127.0.0.1:9443/admin/invite',
    ]);
    const { adminSigningPayload, verifyBytes } = await import('../src/auth.js');
    const headers = (fetch.mock.calls[1][1] as RequestInit).headers as Record<string, string>;
    const payload = adminSigningPayload(
      { method: 'POST', path: '/admin/invite', audience: 'NA-PUBLIC-KEY', body: { roles: ['role:client'] } },
      'operator-local', headers['X-Admin-Timestamp'], headers['X-Admin-Nonce'],
    );
    expect(verifyBytes(Buffer.from(payload), headers['X-Admin-Signature'], TEST_KEY.pubBase64)).toBe(true);
  });

  it('retries the lookup after a failure instead of caching it', async () => {
    const fetch = mockFetch(
      { status: 503, body: { error: 'down' } },
      { status: 200, body: { network_authority: { public_key: 'NA-PUBLIC-KEY' } } },
      { status: 201, body: { token_id: 't1' } },
    );
    const t = buildTransport(fetch, { audience: undefined });
    await expect(t.adminPost('/admin/invite', {})).rejects.toThrow(/NA public key/);
    await expect(t.adminPost('/admin/invite', {})).resolves.toEqual({ token_id: 't1' });
  });
});
