/**
 * Admin authentication for Genesis Mesh NA endpoints.
 *
 * The NA verifies requests via four HTTP headers:
 *   X-Admin-Key-Id        — which operator key was used
 *   X-Admin-Signature     — Ed25519(canonicalJson({body,key_id,nonce,timestamp}))
 *   X-Admin-Timestamp     — ISO 8601 UTC timestamp
 *   X-Admin-Nonce         — UUID v4 replay-protection token
 *
 * Canonical JSON matches Python json.dumps(..., sort_keys=True, separators=(",",":")):
 * keys are recursively sorted, output is compact with no whitespace.
 */

import { createPrivateKey, sign as cryptoSign, randomUUID } from 'node:crypto';

/** Recursively produce compact sorted JSON — stable across Python and Node.js. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']';
  const keys = Object.keys(value as object).sort();
  const pairs = keys.map(k => `${JSON.stringify(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`);
  return '{' + pairs.join(',') + '}';
}

/**
 * PKCS8 DER prefix for an Ed25519 private key.
 * Layout: SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING <seed> } }
 * Concatenate with the 32-byte seed to form a valid PKCS8 DER buffer.
 */
const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

/** Sign raw bytes with an Ed25519 seed (32-byte base64-encoded private key seed). */
export function signBytes(message: Buffer, seedBase64: string): Buffer {
  const seed = Buffer.from(seedBase64, 'base64');
  const pkcs8 = Buffer.concat([ED25519_PKCS8_PREFIX, seed]);
  const privateKey = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  return cryptoSign(null, message, privateKey);
}

export interface AdminHeaders extends Record<string, string> {
  'X-Admin-Key-Id': string;
  'X-Admin-Signature': string;
  'X-Admin-Timestamp': string;
  'X-Admin-Nonce': string;
}

/** Build the four admin auth headers for a given request body. */
export function buildAdminHeaders(
  body: unknown,
  keyId: string,
  signingKeyBase64: string,
): AdminHeaders {
  const timestamp = new Date().toISOString();
  const nonce = randomUUID();
  const canonical = canonicalJson({ body, key_id: keyId, nonce, timestamp });
  const sig = signBytes(Buffer.from(canonical, 'utf-8'), signingKeyBase64);
  return {
    'X-Admin-Key-Id': keyId,
    'X-Admin-Signature': sig.toString('base64'),
    'X-Admin-Timestamp': timestamp,
    'X-Admin-Nonce': nonce,
  };
}
