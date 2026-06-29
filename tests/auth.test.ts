import { canonicalJson, buildAdminHeaders } from '../src/auth.js';
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

describe('buildAdminHeaders', () => {
  it('returns four required headers', () => {
    const headers = buildAdminHeaders({}, 'my-key', TEST_KEY.seedBase64);
    expect(headers['X-Admin-Key-Id']).toBe('my-key');
    expect(typeof headers['X-Admin-Signature']).toBe('string');
    expect(typeof headers['X-Admin-Timestamp']).toBe('string');
    expect(typeof headers['X-Admin-Nonce']).toBe('string');
  });

  it('signature is non-empty base64', () => {
    const headers = buildAdminHeaders({ foo: 'bar' }, 'key', TEST_KEY.seedBase64);
    expect(headers['X-Admin-Signature'].length).toBeGreaterThan(0);
    expect(() => Buffer.from(headers['X-Admin-Signature'], 'base64')).not.toThrow();
  });

  it('signature is 64 bytes (Ed25519)', () => {
    const headers = buildAdminHeaders({}, 'key', TEST_KEY.seedBase64);
    const sigBytes = Buffer.from(headers['X-Admin-Signature'], 'base64');
    expect(sigBytes.length).toBe(64);
  });

  it('produces a unique nonce on each call', () => {
    const h1 = buildAdminHeaders({}, 'key', TEST_KEY.seedBase64);
    const h2 = buildAdminHeaders({}, 'key', TEST_KEY.seedBase64);
    expect(h1['X-Admin-Nonce']).not.toBe(h2['X-Admin-Nonce']);
  });

  it('timestamp is a valid ISO string', () => {
    const headers = buildAdminHeaders({}, 'key', TEST_KEY.seedBase64);
    expect(() => new Date(headers['X-Admin-Timestamp'])).not.toThrow();
    expect(new Date(headers['X-Admin-Timestamp']).toISOString()).toBe(headers['X-Admin-Timestamp']);
  });
});
