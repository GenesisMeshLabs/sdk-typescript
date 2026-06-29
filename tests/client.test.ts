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
      const t = new HttpTransport({ baseUrl: 'http://localhost:9443/' });
      expect((t as unknown as { baseUrl: string }).baseUrl).toBe('http://localhost:9443');
    });

    it('defaults keyId to operator-local', () => {
      const t = new HttpTransport({ baseUrl: 'http://localhost:9443' });
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
      const transport = new HttpTransport({ baseUrl: 'http://localhost:9443' });
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
      const fetch = jest.fn().mockRejectedValue(new Error('ECONNREFUSED'));
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
