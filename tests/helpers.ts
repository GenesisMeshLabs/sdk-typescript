import { generateKeyPairSync } from 'node:crypto';
import { jest } from '@jest/globals';
import { HttpTransport } from '../src/client.js';
import type { ClientOptions } from '../src/client.js';

/** Generate a throwaway Ed25519 key pair for tests. Seed = last 32 bytes of PKCS8 DER. */
export function generateTestKeyPair(): { seedBase64: string; pubBase64: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const pkcs8 = privateKey.export({ type: 'pkcs8', format: 'der' }) as Buffer;
  const spki = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  return {
    seedBase64: pkcs8.slice(-32).toString('base64'),
    pubBase64: spki.slice(-32).toString('base64'),
  };
}

export const TEST_KEY = generateTestKeyPair();

export interface MockResponse {
  status: number;
  body: unknown;
}

/** Returns a jest mock that simulates fetch returning the given responses in order. */
export function mockFetch(...responses: MockResponse[]): jest.Mock {
  let i = 0;
  return jest.fn().mockImplementation(async () => {
    const r = responses[i++] ?? responses[responses.length - 1];
    return {
      ok: r.status >= 200 && r.status < 300,
      status: r.status,
      json: async () => r.body,
    } as Response;
  });
}

/** Build an HttpTransport wired to the provided mock fetch. */
export function buildTransport(
  fetchMock: jest.Mock,
  opts: Partial<ClientOptions> = {},
): HttpTransport {
  return new HttpTransport({
    baseUrl: 'http://127.0.0.1:9443',
    signingKeyBase64: TEST_KEY.seedBase64,
    keyId: 'operator-local',
    fetch: fetchMock as unknown as typeof globalThis.fetch,
    ...opts,
  });
}
