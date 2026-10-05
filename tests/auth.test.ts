import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { adminSigningPayload, buildAdminHeaders, canonicalJson, verifyBytes } from '../src/auth.js';
import { TEST_KEY } from './helpers.js';

describe('canonicalJson', () => {
  it('produces compact output with no whitespace', () => {
    expect(canonicalJson({ a: 1 })).toBe('{"a":1}');
  });

  it('sorts object keys alphabetically', () => {
    expect(canonicalJson({ z: 3, a: 1, m: 2 })).toBe('{"a":1,"m":2,"z":3}');
  });

  it('sorts keys recursively inside nested objects', () => {
    const result = canonicalJson({ outer: { z: 1, a: 2 } });
    expect(result).toBe('{"outer":{"a":2,"z":1}}');
  });

  it('handles arrays without sorting elements', () => {
    expect(canonicalJson([3, 1, 2])).toBe('[3,1,2]');
  });

  it('handles null', () => {
    expect(canonicalJson(null)).toBe('null');
  });

  it('handles strings', () => {
    expect(canonicalJson('hello')).toBe('"hello"');
  });

  it('handles numbers', () => {
    expect(canonicalJson(42)).toBe('42');
  });

  it('handles booleans', () => {
    expect(canonicalJson(true)).toBe('true');
    expect(canonicalJson(false)).toBe('false');
  });

  it('sorts the admin auth canonical message keys correctly', () => {
    const canon = canonicalJson({ body: {}, key_id: 'k', nonce: 'n', timestamp: 't' });
    // Sorted order: body, key_id, nonce, timestamp
    expect(canon).toBe('{"body":{},"key_id":"k","nonce":"n","timestamp":"t"}');
  });

  it('matches Python sort_keys=True output for mixed types', () => {
    const result = canonicalJson({ b: [1, { y: 2, x: 1 }], a: 'str' });
    expect(result).toBe('{"a":"str","b":[1,{"x":1,"y":2}]}');
  });
});

const REQUEST = { method: 'POST', path: '/admin/invite', audience: 'TEST', body: {} };

describe('buildAdminHeaders', () => {
  it('returns four required headers', () => {
    const headers = buildAdminHeaders(REQUEST, 'my-key', TEST_KEY.seedBase64);
    expect(headers['X-Admin-Key-Id']).toBe('my-key');
    expect(typeof headers['X-Admin-Signature']).toBe('string');
    expect(typeof headers['X-Admin-Timestamp']).toBe('string');
    expect(typeof headers['X-Admin-Nonce']).toBe('string');
  });

  it('signature is 64 bytes (Ed25519) over the version 2 payload', () => {
    const headers = buildAdminHeaders({ ...REQUEST, body: { foo: 'bar' } }, 'key', TEST_KEY.seedBase64);
    const sigBytes = Buffer.from(headers['X-Admin-Signature'], 'base64');
    expect(sigBytes.length).toBe(64);
    const payload = adminSigningPayload({ ...REQUEST, body: { foo: 'bar' } }, 'key', headers['X-Admin-Timestamp'], headers['X-Admin-Nonce']);
    expect(verifyBytes(Buffer.from(payload), headers['X-Admin-Signature'], TEST_KEY.pubBase64)).toBe(true);
  });

  it('binds method, path, query and audience', () => {
    const headers = buildAdminHeaders(REQUEST, 'key', TEST_KEY.seedBase64);
    const ts = headers['X-Admin-Timestamp'];
    const nonce = headers['X-Admin-Nonce'];
    for (const other of [
      { ...REQUEST, method: 'PUT' },
      { ...REQUEST, path: '/admin/revoke' },
      { ...REQUEST, query: { limit: '1' } },
      { ...REQUEST, audience: 'OTHER' },
    ]) {
      const payload = adminSigningPayload(other, 'key', ts, nonce);
      expect(verifyBytes(Buffer.from(payload), headers['X-Admin-Signature'], TEST_KEY.pubBase64)).toBe(false);
    }
  });

  it('refuses a relative path but signs a decoded "?" inside a path', () => {
    expect(() => buildAdminHeaders({ ...REQUEST, path: 'admin/invite' }, 'key', TEST_KEY.seedBase64)).toThrow();
    expect(adminSigningPayload({ ...REQUEST, path: '/admin/attestations/a?b/revoke' }, 'k', 't', 'n'))
      .toContain('"path":"/admin/attestations/a?b/revoke"');
  });

  it('produces a unique nonce on each call', () => {
    const h1 = buildAdminHeaders(REQUEST, 'key', TEST_KEY.seedBase64);
    const h2 = buildAdminHeaders(REQUEST, 'key', TEST_KEY.seedBase64);
    expect(h1['X-Admin-Nonce']).not.toBe(h2['X-Admin-Nonce']);
  });

  it('timestamp is a valid ISO string', () => {
    const headers = buildAdminHeaders(REQUEST, 'key', TEST_KEY.seedBase64);
    expect(new Date(headers['X-Admin-Timestamp']).toISOString()).toBe(headers['X-Admin-Timestamp']);
  });
});

/** Shared reference vectors (genesismesh/conformance/vectors/admin_auth.json), copied unchanged. */
describe('admin signature conformance vectors', () => {
  const raw = readFileSync(fileURLToPath(new URL('./fixtures/conformance/admin_auth.json', import.meta.url)), 'utf-8');
  const suite = JSON.parse(raw) as { vectors: Array<{ id: string; input: Record<string, any>; expected: Record<string, string> }> };
  // Seed "a" of the reference suite: bytes 0..31.
  const seedA = Buffer.from(Array.from({ length: 32 }, (_, i) => i)).toString('base64');

  it.each(suite.vectors.map(v => [v.id, v] as const))('%s', (_id, v) => {
    const i = v.input;
    const request = { method: i.method, path: i.path, query: i.query, audience: i.audience, body: i.body };
    expect(adminSigningPayload(request, i.key_id, i.timestamp, i.nonce)).toBe(v.expected.payload);
    const headers = buildAdminHeaders(request, i.key_id, seedA, { timestamp: i.timestamp, nonce: i.nonce });
    expect(headers['X-Admin-Signature']).toBe(v.expected.signature_b64);
  });
});
